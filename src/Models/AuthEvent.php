<?php

namespace Kiddoflow\AuthLog\Models;

use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\MassPrunable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\MorphTo;
use Kiddoflow\AuthLog\Database\Factories\AuthEventFactory;
use Kiddoflow\AuthLog\Enums\AuthEventType;

/**
 * One entry in the sign-in history. Failed sign-ins for an email address
 * with no account have no authenticatable, only the email typed.
 *
 * @property AuthEventType $type
 * @property string|null $email
 * @property string|null $ip_address
 * @property string|null $user_agent
 * @property string|null $country
 * @property string|null $city
 * @property bool $is_suspicious
 * @property list<string>|null $suspicion_reasons
 * @property CarbonInterface $created_at
 */
class AuthEvent extends Model
{
    /** @use HasFactory<AuthEventFactory> */
    use HasFactory, MassPrunable;

    public const UPDATED_AT = null;

    protected $table = 'auth_events';

    protected $guarded = ['id'];

    protected static function newFactory(): AuthEventFactory
    {
        return AuthEventFactory::new();
    }

    protected function casts(): array
    {
        return [
            'type' => AuthEventType::class,
            'is_suspicious' => 'boolean',
            'suspicion_reasons' => 'array',
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
     * @return BelongsTo<Device, $this>
     */
    public function device(): BelongsTo
    {
        return $this->belongsTo(Device::class);
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
     * Events older than the retention period.
     *
     * @return Builder<self>
     */
    public function prunable(): Builder
    {
        return static::query()->where('created_at', '<', now()->subDays((int) config('auth-log.retention_days')));
    }
}
