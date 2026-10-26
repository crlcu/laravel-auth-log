<?php

namespace Kiddoflow\AuthLog\Enums;

enum AuthEventType: string
{
    case Login = 'login';
    case Logout = 'logout';
    case Failed = 'failed';
    case Lockout = 'lockout';
    case PasswordReset = 'password_reset';
    case DeviceSignedOut = 'device_signed_out';
    case VerificationSent = 'verification_sent';
    case Verified = 'verified';
    case VerificationFailed = 'verification_failed';

    /**
     * Whether the event is a sign-in that went wrong, worth drawing attention to.
     */
    public function isFailure(): bool
    {
        return match ($this) {
            self::Failed, self::Lockout, self::VerificationFailed => true,
            default => false,
        };
    }
}
