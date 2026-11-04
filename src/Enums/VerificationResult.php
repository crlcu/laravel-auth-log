<?php

namespace Crlcu\AuthLog\Enums;

enum VerificationResult
{
    case Verified;
    case Invalid;
    case Expired;

    /**
     * Too many wrong codes: the device was signed out.
     */
    case TooManyAttempts;
}
