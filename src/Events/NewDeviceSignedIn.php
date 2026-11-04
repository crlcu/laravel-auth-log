<?php

namespace Crlcu\AuthLog\Events;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Foundation\Events\Dispatchable;
use Crlcu\AuthLog\Models\AuthEvent;
use Crlcu\AuthLog\Models\Device;

/**
 * A user who already had a device signed in from one they never used before.
 * Not dispatched for a user's first device, nor for a flagged sign-in, which
 * gets a verification code instead.
 */
class NewDeviceSignedIn
{
    use Dispatchable;

    public function __construct(
        public Model $user,
        public Device $device,
        public AuthEvent $event,
    ) {}
}
