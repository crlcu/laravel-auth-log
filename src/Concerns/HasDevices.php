<?php

namespace Kiddoflow\AuthLog\Concerns;

use Illuminate\Database\Eloquent\Relations\MorphMany;
use Kiddoflow\AuthLog\Models\AuthEvent;
use Kiddoflow\AuthLog\Models\Device;

/**
 * Tracks the devices and sign-in history of an authenticatable model.
 */
trait HasDevices
{
    /**
     * @return MorphMany<Device, $this>
     */
    public function devices(): MorphMany
    {
        return $this->morphMany(Device::class, 'authenticatable');
    }

    /**
     * @return MorphMany<AuthEvent, $this>
     */
    public function authEvents(): MorphMany
    {
        return $this->morphMany(AuthEvent::class, 'authenticatable');
    }
}
