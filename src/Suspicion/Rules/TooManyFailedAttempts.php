<?php

namespace Crlcu\AuthLog\Suspicion\Rules;

use Illuminate\Database\Eloquent\Model;
use Crlcu\AuthLog\Enums\AuthEventType;
use Crlcu\AuthLog\Location\Location;
use Crlcu\AuthLog\Models\AuthEvent;
use Crlcu\AuthLog\Suspicion\Rule;

/**
 * Someone got the password right after many wrong guesses on the account.
 */
class TooManyFailedAttempts implements Rule
{
    public const REASON = 'too_many_failed_attempts';

    public function check(Model $user, Location $location): ?string
    {
        $failedAttempts = AuthEvent::query()
            ->forAuthenticatable($user)
            ->where('type', AuthEventType::Failed)
            ->where('created_at', '>=', now()->subMinutes((int) config('auth-log.suspicion.failed_attempts_window_minutes')))
            ->count();

        return $failedAttempts >= (int) config('auth-log.suspicion.failed_attempts_threshold') ? self::REASON : null;
    }
}
