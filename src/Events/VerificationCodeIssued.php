<?php

namespace Kiddoflow\AuthLog\Events;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Foundation\Events\Dispatchable;
use Kiddoflow\AuthLog\Models\Device;

/**
 * A device needs the code before it can be used. The app sends the code;
 * only its hash is stored.
 */
class VerificationCodeIssued
{
    use Dispatchable;

    /**
     * @param  list<string>  $reasons  why the sign-in was flagged
     */
    public function __construct(
        public Model $user,
        public Device $device,
        #[\SensitiveParameter] public string $code,
        public array $reasons,
    ) {}
}
