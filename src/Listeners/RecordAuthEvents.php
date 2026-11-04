<?php

namespace Crlcu\AuthLog\Listeners;

use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Lockout;
use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Events\Dispatcher;
use Illuminate\Support\Arr;
use Crlcu\AuthLog\Enums\AuthEventType;
use Crlcu\AuthLog\Tracker;

/**
 * The sign-in events the guard does not see itself: wrong passwords,
 * throttled sign-ins and password resets.
 */
class RecordAuthEvents
{
    public function __construct(private Tracker $tracker) {}

    public function handleFailed(Failed $event): void
    {
        $email = Arr::get($event->credentials, 'email');

        $this->tracker->recordFailedLogin($event->user instanceof Model ? $event->user : null, is_string($email) ? $email : null);
    }

    public function handleLockout(Lockout $event): void
    {
        $email = $event->request->input('email');

        $this->tracker->record(AuthEventType::Lockout, null, email: is_string($email) ? $email : null);
    }

    /**
     * Whoever knew the old password may still be signed in: a reset signs
     * every device out.
     */
    public function handlePasswordReset(PasswordReset $event): void
    {
        if (! Tracker::tracks($event->user)) {
            return;
        }

        $this->tracker->record(AuthEventType::PasswordReset, $event->user);
        $this->tracker->signOutOtherDevices($event->user);
    }

    /**
     * @return array<class-string, string>
     */
    public function subscribe(Dispatcher $events): array
    {
        return [
            Failed::class => 'handleFailed',
            Lockout::class => 'handleLockout',
            PasswordReset::class => 'handlePasswordReset',
        ];
    }
}
