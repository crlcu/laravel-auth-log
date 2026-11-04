<?php

use Crlcu\AuthLog\Location\CloudflareLocationResolver;
use Crlcu\AuthLog\Suspicion\Rules\NewCountry;
use Crlcu\AuthLog\Suspicion\Rules\TooManyFailedAttempts;

return [

    /*
    |--------------------------------------------------------------------------
    | Device cookie
    |--------------------------------------------------------------------------
    |
    | Each browser is told apart by a random value kept in this cookie, rather
    | than a fingerprint of its headers or IP address, so a new IP is still the
    | same device. Clearing cookies makes the browser a new device.
    |
    */

    'cookie' => [
        'name' => env('AUTH_LOG_COOKIE', 'device_id'),
        'lifetime_minutes' => 60 * 24 * 365 * 5,
    ],

    /*
    |--------------------------------------------------------------------------
    | Retention
    |--------------------------------------------------------------------------
    |
    | Sign-in events, and devices not seen for this many days, are pruned by
    | `php artisan model:prune`. IP addresses and devices are personal data.
    |
    */

    'retention_days' => 365,

    /*
    |--------------------------------------------------------------------------
    | Activity
    |--------------------------------------------------------------------------
    |
    | How often a device's last-seen time, IP address and location are written
    | while it is in use.
    |
    */

    'activity_throttle_minutes' => 5,

    /*
    |--------------------------------------------------------------------------
    | Location
    |--------------------------------------------------------------------------
    */

    'location_resolver' => CloudflareLocationResolver::class,

    /*
    |--------------------------------------------------------------------------
    | Suspicious sign-ins
    |--------------------------------------------------------------------------
    |
    | Each rule may flag a sign-in. A flagged device must enter a code sent by
    | email before it can be used, unless AuthLog::skipVerificationWhen()
    | says the user already proved themselves, e.g. with two-factor.
    |
    */

    'suspicion' => [
        'rules' => [
            TooManyFailedAttempts::class,
            NewCountry::class,
        ],

        'failed_attempts_threshold' => 5,
        'failed_attempts_window_minutes' => 60,
        'known_country_days' => 90,
    ],

    /*
    |--------------------------------------------------------------------------
    | Verification codes
    |--------------------------------------------------------------------------
    |
    | Requests from a device awaiting its code are sent to `route`, except to
    | the routes in `allowed_routes`, so the user can still enter the code or
    | sign out.
    |
    | `max_attempts` wrong codes per user within `attempts_window_minutes`
    | sign the device out; neither a new code nor a new sign-in resets them.
    |
    */

    'verification' => [
        'route' => 'device-verification.show',
        'allowed_routes' => ['device-verification.*', 'logout'],
        'code_lifetime_minutes' => 15,
        'max_attempts' => 5,
        'attempts_window_minutes' => 60,
        'resend_cooldown_seconds' => 60,
    ],

    /*
    |--------------------------------------------------------------------------
    | Signed-out devices
    |--------------------------------------------------------------------------
    |
    | Where a request from a device that was signed out elsewhere is sent.
    |
    */

    'signed_out_route' => 'login',

];
