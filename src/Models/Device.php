<?php

namespace Crlcu\AuthLog\Models;

use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\MassPrunable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\Relations\MorphTo;
use Crlcu\AuthLog\Database\Factories\DeviceFactory;

/**
 * One browser a user signed in from, told apart by the device cookie.
 *
 * A device is signed in until signed_out_at is set, and stays usable while
 * it holds a remember token or its session has not expired. A device with
 * no verified_at is waiting for the code emailed after a suspicious sign-in.
 *
 * @property string|null $session_id
 * @property string|null $browser
 * @property string|null $platform
 * @property string|null $ip_address
 * @property string|null $country
 * @property string|null $city
 * @property CarbonInterface $first_seen_at
 * @property CarbonInterface $last_seen_at
 * @property CarbonInterface|null $verified_at
 * @property CarbonInterface|null $verification_sent_at
 * @property CarbonInterface|null $signed_out_at
 */
class Device extends Model
{
    /** @use HasFactory<DeviceFactory> */
    use HasFactory, MassPrunable;

    protected $table = 'auth_devices';

    protected $guarded = ['id'];

    protected $hidden = [
        'device_token_hash',
        'remember_token_hash',
        'session_id',
        'verification_code_hash',
    ];

    protected static function newFactory(): DeviceFactory
    {
        return DeviceFactory::new();
    }

    protected function casts(): array
    {
        return [
            'first_seen_at' => 'datetime',
            'last_seen_at' => 'datetime',
            'verified_at' => 'datetime',
            'verification_sent_at' => 'datetime',
            'signed_out_at' => 'datetime',
        ];
    }

    /**
     * @return MorphTo<Model, $this>
     */
    public function authenticatable(): MorphTo
    {
        return $this->morphTo();
    }

    /**
     * @return HasMany<AuthEvent, $this>
     */
    public function events(): HasMany
    {
        return $this->hasMany(AuthEvent::class);
    }

    /**
     * @param  Builder<self>  $query
     */
    public function scopeForAuthenticatable(Builder $query, Model $authenticatable): void
    {
        $query->where('authenticatable_type', $authenticatable->getMorphClass())
            ->where('authenticatable_id', $authenticatable->getKey());
    }

    /**
     * Devices still signed in: remembered, or used within the session lifetime.
     *
     * @param  Builder<self>  $query
     */
    public function scopeSignedIn(Builder $query): void
    {
        $query->whereNull('signed_out_at')
            ->where(fn (Builder $query) => $query
                ->whereNotNull('remember_token_hash')
                ->orWhere('last_seen_at', '>=', now()->subMinutes((int) config('session.lifetime'))));
    }

    public function isSignedOut(): bool
    {
        return $this->signed_out_at !== null;
    }

    public function isAwaitingVerification(): bool
    {
        return $this->verified_at === null;
    }

    public function verificationCodeHasExpired(): bool
    {
        return $this->verification_sent_at === null
            || $this->verification_sent_at->lte(now()->subMinutes((int) config('auth-log.verification.code_lifetime_minutes')));
    }

    /**
     * Devices not seen for longer than the retention period.
     *
     * @return Builder<self>
     */
    public function prunable(): Builder
    {
        return static::query()->where('last_seen_at', '<', now()->subDays((int) config('auth-log.retention_days')));
    }
}
