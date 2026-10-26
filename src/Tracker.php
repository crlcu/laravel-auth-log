<?php

namespace Kiddoflow\AuthLog;

use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Cookie\CookieJar;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Session\Store;
use Illuminate\Support\Str;
use Kiddoflow\AuthLog\Concerns\HasDevices;
use Kiddoflow\AuthLog\Device\UserAgent;
use Kiddoflow\AuthLog\Enums\AuthEventType;
use Kiddoflow\AuthLog\Enums\VerificationResult;
use Kiddoflow\AuthLog\Events\NewDeviceSignedIn;
use Kiddoflow\AuthLog\Events\VerificationCodeIssued;
use Kiddoflow\AuthLog\Location\Location;
use Kiddoflow\AuthLog\Location\LocationResolver;
use Kiddoflow\AuthLog\Models\AuthEvent;
use Kiddoflow\AuthLog\Models\Device;
use Kiddoflow\AuthLog\Suspicion\Detector;
use Kiddoflow\AuthLog\Suspicion\Rules\TooManyFailedAttempts;

/**
 * Records sign-ins against the device they come from and manages those
 * devices' sessions. Bound per request (scoped), so the quiet flag and the
 * device cookie issued during a request never leak into the next one.
 */
class Tracker
{
    /**
     * Session key holding the id of the device the session belongs to.
     */
    public const SESSION_KEY = 'auth_log_device_id';

    private bool $quiet = false;

    private ?string $issuedDeviceToken = null;

    public function __construct(
        private Container $container,
        private Detector $detector,
        private LocationResolver $locationResolver,
    ) {}

    /**
     * Whether sign-ins of this user are tracked: a model using HasDevices.
     */
    public static function tracks(mixed $user): bool
    {
        return $user instanceof Model && in_array(HasDevices::class, class_uses_recursive($user), true);
    }

    /**
     * Run the callback without recording events, checking for suspicious
     * sign-ins or sending anything. Devices and remember tokens are still kept
     * up to date, so the session keeps working.
     *
     * @template TReturn
     *
     * @param  callable(): TReturn  $callback
     * @return TReturn
     */
    public function withoutTracking(callable $callback): mixed
    {
        $wasQuiet = $this->quiet;
        $this->quiet = true;

        try {
            return $callback();
        } finally {
            $this->quiet = $wasQuiet;
        }
    }

    /**
     * Record a fresh sign-in (not a remember-me restore) and tie the session to the device.
     */
    public function signIn(Model $user): Device
    {
        $request = $this->request();
        $deviceToken = $this->deviceToken($request, issue: true);
        $device = $this->findByDeviceToken($user, $deviceToken);
        $isNewDevice = $device === null;
        $hadOtherDevices = $isNewDevice && Device::query()->forAuthenticatable($user)->exists();
        $location = $this->locationResolver->resolve($request);

        $reasons = $this->quiet ? [] : $this->detector->detect($user, $location);
        $needsCode = ! $this->quiet
            && (($reasons !== [] && ! AuthLog::skipsVerificationFor($user)) || ($device?->isAwaitingVerification() ?? false));

        $device ??= $this->newDevice($user, $deviceToken);
        $this->fillFromRequest($device, $request, $location);
        $device->signed_out_at = null;
        $device->save();

        $this->session()->put(self::SESSION_KEY, $device->getKey());

        if ($this->quiet) {
            return $device;
        }

        $event = $this->record(AuthEventType::Login, $user, $device, $reasons);

        if ($needsCode) {
            $this->issueVerificationCode($user, $device, $reasons);
        } elseif ($isNewDevice && $hadOtherDevices) {
            NewDeviceSignedIn::dispatch($user, $device, $event);
        }

        return $device;
    }

    /**
     * A remembered device came back after its session expired.
     */
    public function restore(Model $user, Device $device): void
    {
        $request = $this->request();

        $this->fillFromRequest($device, $request, $this->locationResolver->resolve($request));
        $device->save();

        $this->session()->put(self::SESSION_KEY, $device->getKey());
    }

    /**
     * Take on a session that has no device yet, such as one started before
     * tracking was installed, without alerting anyone.
     */
    public function adopt(Model $user): Device
    {
        return $this->withoutTracking(fn () => $this->signIn($user));
    }

    /**
     * The device the current session belongs to.
     */
    public function currentDevice(Model $user): ?Device
    {
        $deviceId = $this->session()->get(self::SESSION_KEY);

        return $deviceId === null ? null : Device::query()->forAuthenticatable($user)->find($deviceId);
    }

    /**
     * Keep the device's last-seen time, session, IP address and location
     * current, writing at most once per throttle period unless the session or
     * IP address changed.
     */
    public function touch(Device $device): void
    {
        $request = $this->request();

        $isFresh = $device->last_seen_at->gt(now()->subMinutes((int) config('auth-log.activity_throttle_minutes')));

        if ($isFresh && $device->session_id === $this->session()->getId() && $device->ip_address === $request->ip()) {
            return;
        }

        $this->fillFromRequest($device, $request, $this->locationResolver->resolve($request));
        $device->save();
    }

    /**
     * The user signed out of the current device.
     */
    public function signOut(Model $user): void
    {
        $device = $this->currentDevice($user);

        $this->session()->forget(self::SESSION_KEY);

        if ($device === null) {
            return;
        }

        $device->forceFill([
            'signed_out_at' => now(),
            'remember_token_hash' => null,
            'session_id' => null,
        ])->save();

        if (! $this->quiet) {
            $this->record(AuthEventType::Logout, $user, $device);
        }
    }

    /**
     * Sign a device out from elsewhere: its session is destroyed and its
     * remember token cleared, so it has to sign in again. The current
     * session is left to the caller to end.
     *
     * A browser may still hold a "remember me" cookie made before devices had
     * their own token, which would bring it straight back, so those cookies
     * stop working too.
     */
    public function signOutDevice(Model $user, Device $device): void
    {
        $this->endDevice($user, $device);

        $this->cycleLegacyRememberToken($user);
    }

    /**
     * Sign out every device of the user but the given one.
     *
     * @return int the number of devices signed out
     */
    public function signOutOtherDevices(Model $user, ?Device $except = null): int
    {
        $devices = Device::query()
            ->forAuthenticatable($user)
            ->whereNull('signed_out_at')
            ->when($except, fn ($query) => $query->whereKeyNot($except->getKey()))
            ->get();

        $devices->each(fn (Device $device) => $this->endDevice($user, $device));

        $this->cycleLegacyRememberToken($user);

        return $devices->count();
    }

    /**
     * The device a "remember me" token belongs to, if it is still signed in.
     */
    public function findByRememberToken(Model $user, string $token): ?Device
    {
        if (! self::isDeviceRememberToken($token)) {
            return null;
        }

        [$deviceId, $secret] = explode(':', $token, 2);

        $device = Device::query()
            ->forAuthenticatable($user)
            ->whereNull('signed_out_at')
            ->whereNotNull('remember_token_hash')
            ->find($deviceId);

        return $device !== null && hash_equals($device->remember_token_hash, hash('sha256', $secret)) ? $device : null;
    }

    /**
     * Give the device a new "remember me" token, returned for the cookie.
     */
    public function issueRememberToken(Device $device): string
    {
        $secret = Str::random(60);

        $device->forceFill(['remember_token_hash' => hash('sha256', $secret)])->save();

        return $device->getKey().':'.$secret;
    }

    /**
     * Tokens issued per device look like "{device id}:{60 characters}";
     * older cookies hold the user's single remember token instead.
     */
    public static function isDeviceRememberToken(string $token): bool
    {
        return (bool) preg_match('/^\d+:[A-Za-z0-9]{60}$/', $token);
    }

    /**
     * Send a new code, unless one went out moments ago.
     */
    public function resendVerificationCode(Model $user, Device $device): bool
    {
        if (! $device->isAwaitingVerification()) {
            return false;
        }

        if ($device->verification_sent_at?->gt(now()->subSeconds((int) config('auth-log.verification.resend_cooldown_seconds')))) {
            return false;
        }

        $lastSignIn = $device->events()
            ->where('type', AuthEventType::Login)
            ->latest('id')
            ->first();

        $this->issueVerificationCode($user, $device, $lastSignIn->suspicion_reasons ?? []);

        return true;
    }

    /**
     * Check a code typed on the device.
     *
     * Wrong codes are counted per user over a time window, from the history,
     * and nothing resets the count: not a new code, not signing in again with
     * the password, not a new device. Whoever stole the password therefore
     * gets a handful of guesses an hour. Reaching the limit signs the device
     * out. A lock per user keeps parallel requests from guessing past it.
     */
    public function verify(Model $user, Device $device, #[\SensitiveParameter] string $code): VerificationResult
    {
        $lock = $this->container->make(CacheRepository::class)
            ->lock('auth-log:verify:'.$user->getMorphClass().':'.$user->getKey(), 10);

        return $lock->block(5, function () use ($user, $device, $code) {
            $device->refresh();

            if (! $device->isAwaitingVerification()) {
                return VerificationResult::Verified;
            }

            if ($this->hasTooManyWrongCodes($user)) {
                $this->signOutDevice($user, $device);

                return VerificationResult::TooManyAttempts;
            }

            if ($device->verificationCodeHasExpired()) {
                return VerificationResult::Expired;
            }

            if (hash_equals((string) $device->verification_code_hash, $this->hashCode($code))) {
                $device->forceFill([
                    'verified_at' => now(),
                    'verification_code_hash' => null,
                ])->save();

                $this->record(AuthEventType::Verified, $user, $device);

                return VerificationResult::Verified;
            }

            $this->record(AuthEventType::VerificationFailed, $user, $device);

            if ($this->hasTooManyWrongCodes($user)) {
                $this->signOutDevice($user, $device);

                return VerificationResult::TooManyAttempts;
            }

            return VerificationResult::Invalid;
        });
    }

    private function hasTooManyWrongCodes(Model $user): bool
    {
        $wrongCodes = AuthEvent::query()
            ->forAuthenticatable($user)
            ->where('type', AuthEventType::VerificationFailed)
            ->where('created_at', '>=', now()->subMinutes((int) config('auth-log.verification.attempts_window_minutes')))
            ->count();

        return $wrongCodes >= (int) config('auth-log.verification.max_attempts');
    }

    /**
     * Someone typed a wrong password. The user is null when no account has the email.
     */
    public function recordFailedLogin(?Model $user, ?string $email): AuthEvent
    {
        $user = self::tracks($user) ? $user : null;

        $deviceToken = $this->deviceToken($this->request(), issue: false);
        $device = $user !== null && $deviceToken !== null ? $this->findByDeviceToken($user, $deviceToken) : null;

        $event = $this->record(AuthEventType::Failed, $user, $device, email: $email);

        if ($user !== null && ($reason = $this->container->make(TooManyFailedAttempts::class)->check($user, new Location))) {
            $event->forceFill(['is_suspicious' => true, 'suspicion_reasons' => [$reason]])->save();
        }

        return $event;
    }

    /**
     * Add an entry to the sign-in history, with where the current request came from.
     *
     * @param  list<string>  $reasons
     */
    public function record(AuthEventType $type, ?Model $user, ?Device $device = null, array $reasons = [], ?string $email = null): AuthEvent
    {
        $request = $this->request();
        $location = $this->locationResolver->resolve($request);

        return AuthEvent::query()->create([
            'authenticatable_type' => $user?->getMorphClass(),
            'authenticatable_id' => $user?->getKey(),
            'device_id' => $device?->getKey(),
            'type' => $type,
            'email' => $email !== null ? Str::limit(Str::lower($email), 255, '') : null,
            'ip_address' => $request->ip(),
            'user_agent' => $request->userAgent() !== null ? Str::limit($request->userAgent(), 1024, '') : null,
            'country' => $location->country,
            'city' => $location->city,
            'is_suspicious' => $reasons !== [],
            'suspicion_reasons' => $reasons !== [] ? $reasons : null,
            'created_at' => now(),
        ]);
    }

    private function endDevice(Model $user, Device $device): void
    {
        if ($device->session_id !== null && $device->session_id !== $this->session()->getId()) {
            $this->session()->getHandler()->destroy($device->session_id);
        }

        $device->forceFill([
            'signed_out_at' => now(),
            'remember_token_hash' => null,
            'session_id' => null,
        ])->save();

        $this->record(AuthEventType::DeviceSignedOut, $user, $device);
    }

    /**
     * @param  list<string>  $reasons
     */
    private function issueVerificationCode(Model $user, Device $device, array $reasons): void
    {
        $code = str_pad((string) random_int(0, 999999), 6, '0', STR_PAD_LEFT);

        $device->forceFill([
            'verified_at' => null,
            'verification_code_hash' => $this->hashCode($code),
            'verification_sent_at' => now(),
        ])->save();

        $this->record(AuthEventType::VerificationSent, $user, $device);

        VerificationCodeIssued::dispatch($user, $device, $code, $reasons);
    }

    private function hashCode(#[\SensitiveParameter] string $code): string
    {
        return hash_hmac('sha256', $code, (string) config('app.key'));
    }

    private function newDevice(Model $user, string $deviceToken): Device
    {
        $device = new Device([
            'device_token_hash' => hash('sha256', $deviceToken),
            'first_seen_at' => now(),
            'verified_at' => now(),
        ]);

        $device->authenticatable()->associate($user);

        return $device;
    }

    private function fillFromRequest(Device $device, Request $request, Location $location): void
    {
        $userAgent = UserAgent::parse($request->userAgent());

        $device->fill([
            'session_id' => $this->session()->getId(),
            'browser' => $userAgent->browser,
            'platform' => $userAgent->platform,
            'ip_address' => $request->ip(),
            'country' => $location->country,
            'city' => $location->city,
            'last_seen_at' => now(),
        ]);
    }

    private function findByDeviceToken(Model $user, string $deviceToken): ?Device
    {
        return Device::query()
            ->forAuthenticatable($user)
            ->where('device_token_hash', hash('sha256', $deviceToken))
            ->first();
    }

    /**
     * The random value in the device cookie, issuing one when asked and the
     * browser has none.
     *
     * @return ($issue is true ? string : string|null)
     */
    private function deviceToken(Request $request, bool $issue): ?string
    {
        if ($this->issuedDeviceToken !== null) {
            return $this->issuedDeviceToken;
        }

        $value = $request->cookie((string) config('auth-log.cookie.name'));

        if (is_string($value) && preg_match('/^[A-Za-z0-9]{40}$/', $value)) {
            return $value;
        }

        if (! $issue) {
            return null;
        }

        $this->issuedDeviceToken = Str::random(40);

        $cookies = $this->container->make(CookieJar::class);
        $cookies->queue($cookies->make(
            (string) config('auth-log.cookie.name'),
            $this->issuedDeviceToken,
            (int) config('auth-log.cookie.lifetime_minutes'),
        ));

        return $this->issuedDeviceToken;
    }

    /**
     * Before devices had their own token, every remembered browser shared the
     * user's; changing it signs those browsers out.
     */
    private function cycleLegacyRememberToken(Model $user): void
    {
        if (! method_exists($user, 'getRememberTokenName') || $user->getRememberTokenName() === '' || $user->getRememberToken() === null) {
            return;
        }

        $user->setRememberToken(Str::random(60));
        $user::withoutTimestamps(fn () => $user->saveQuietly());
    }

    private function request(): Request
    {
        return $this->container->make('request');
    }

    private function session(): Store
    {
        return $this->container->make('session.store');
    }
}
