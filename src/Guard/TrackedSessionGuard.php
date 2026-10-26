<?php

namespace Kiddoflow\AuthLog\Guard;

use Illuminate\Auth\Recaller;
use Illuminate\Auth\SessionGuard;
use Illuminate\Container\Container;
use Illuminate\Contracts\Auth\Authenticatable as AuthenticatableContract;
use Illuminate\Database\Eloquent\Model;
use Kiddoflow\AuthLog\Models\Device;
use Kiddoflow\AuthLog\Tracker;

/**
 * Laravel's session guard, with every sign-in recorded against the device it
 * comes from and a "remember me" token per device instead of one per user,
 * so one device can be signed out without signing out the others.
 *
 * Cookies holding the user's single remember token, issued before this guard,
 * keep working and are swapped for a device token on first use.
 */
class TrackedSessionGuard extends SessionGuard
{
    /**
     * The device whose remember token signed the user in on this request.
     */
    private ?Device $recalledDevice = null;

    public function user()
    {
        $isResolving = $this->user === null && ! $this->loggedOut;

        $user = parent::user();

        if ($isResolving && $user !== null && $this->viaRemember && Tracker::tracks($user)) {
            if ($this->recalledDevice !== null) {
                $this->tracker()->restore($user, $this->recalledDevice);
            } else {
                $this->queueDeviceRecaller($user, $this->tracker()->adopt($user));
            }
        }

        return $user;
    }

    /**
     * @param  Recaller  $recaller
     */
    protected function userFromRecaller($recaller)
    {
        if (! $recaller->valid() || $this->recallAttempted) {
            return null;
        }

        if (! Tracker::isDeviceRememberToken($recaller->token())) {
            return parent::userFromRecaller($recaller);
        }

        $this->recallAttempted = true;

        $user = $this->provider->retrieveById($recaller->id());

        $device = Tracker::tracks($user) ? $this->tracker()->findByRememberToken($user, $recaller->token()) : null;

        // Users who signed up with Google or Yahoo have no password; their cookie
        // carries the hash of an empty one, which a password set later invalidates.
        if ($device === null || ! hash_equals($this->hashPasswordForCookie($user->getAuthPassword()), $recaller->hash())) {
            return null;
        }

        $this->viaRemember = true;
        $this->recalledDevice = $device;

        return $user;
    }

    public function login(AuthenticatableContract $user, $remember = false)
    {
        if (! Tracker::tracks($user)) {
            parent::login($user, $remember);

            return;
        }

        $this->updateSession($user->getAuthIdentifier());

        if ($passwordHash = $user->getAuthPassword()) {
            $this->session->put('password_hash_'.$this->name, $this->hashPasswordForCookie($passwordHash));
        }

        $device = $this->tracker()->signIn($user);

        if ($remember) {
            $this->queueDeviceRecaller($user, $device);
        }

        $this->fireLoginEvent($user, $remember);

        $this->setUser($user);
    }

    public function logout()
    {
        $user = $this->user();

        if (Tracker::tracks($user)) {
            $this->tracker()->signOut($user);
        }

        parent::logout();
    }

    public function logoutCurrentDevice()
    {
        $user = $this->user();

        if (Tracker::tracks($user)) {
            $this->tracker()->signOut($user);
        }

        parent::logoutCurrentDevice();
    }

    /**
     * Laravel's version, which also signs the other devices out for real, so
     * the AuthenticateSession middleware is not needed.
     */
    public function logoutOtherDevices(#[\SensitiveParameter] $password)
    {
        parent::logoutOtherDevices($password);

        $user = $this->user();

        if (Tracker::tracks($user)) {
            $this->tracker()->signOutOtherDevices($user, $this->tracker()->currentDevice($user));
        }
    }

    /**
     * Sign in without firing the Login event or recording anything. Used by
     * lab404/laravel-impersonate to switch to and back from the impersonated user.
     */
    public function quietLogin(AuthenticatableContract $user): void
    {
        $this->updateSession($user->getAuthIdentifier());

        $this->setUser($user);
    }

    /**
     * Sign out without firing the Logout event or changing any remember
     * token. Used by lab404/laravel-impersonate.
     */
    public function quietLogout(): void
    {
        $this->clearUserDataFromStorage();

        $this->user = null;

        $this->loggedOut = true;
    }

    protected function queueRecallerCookie(AuthenticatableContract $user)
    {
        $device = Tracker::tracks($user) ? $this->tracker()->currentDevice($user) : null;

        if ($device === null) {
            parent::queueRecallerCookie($user);

            return;
        }

        $this->queueDeviceRecaller($user, $device);
    }

    private function queueDeviceRecaller(Model&AuthenticatableContract $user, Device $device): void
    {
        $this->getCookieJar()->queue($this->createRecaller(
            $user->getAuthIdentifier().'|'.
            $this->tracker()->issueRememberToken($device).'|'.
            $this->hashPasswordForCookie($user->getAuthPassword())
        ));
    }

    private function tracker(): Tracker
    {
        return Container::getInstance()->make(Tracker::class);
    }
}
