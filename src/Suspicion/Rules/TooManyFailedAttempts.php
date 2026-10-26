<?php

namespace Kiddoflow\AuthLog\Suspicion\Rules;

use Illuminate\Database\Eloquent\Model;
use Kiddoflow\AuthLog\Enums\AuthEventType;
use Kiddoflow\AuthLog\Location\Location;
use Kiddoflow\AuthLog\Models\AuthEvent;
use Kiddoflow\AuthLog\Suspicion\Rule;

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
