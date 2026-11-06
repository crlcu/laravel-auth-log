<?php

use Crlcu\AuthLog\Location\CloudflareLocationResolver;
use Crlcu\AuthLog\Suspicion\Rules\NewCountry;
use Crlcu\AuthLog\Suspicion\Rules\TooManyFailedAttempts;

/*
|--------------------------------------------------------------------------
| Environment
|--------------------------------------------------------------------------
|
| These can be changed per environment without publishing this file:
| AUTH_LOG_COOKIE, AUTH_LOG_COOKIE_LIFETIME (minutes), AUTH_LOG_RETENTION_DAYS,
| AUTH_LOG_ACTIVITY_THROTTLE (minutes), AUTH_LOG_FAILED_ATTEMPTS_THRESHOLD,
| AUTH_LOG_FAILED_ATTEMPTS_WINDOW (minutes), AUTH_LOG_KNOWN_COUNTRY_DAYS,
| AUTH_LOG_CODE_LIFETIME (minutes), AUTH_LOG_CODE_MAX_ATTEMPTS,
| AUTH_LOG_CODE_ATTEMPTS_WINDOW (minutes), AUTH_LOG_CODE_RESEND_COOLDOWN
| (seconds) and AUTH_LOG_KNOWN_ACCOUNTS_LIMIT. Class names, routes, the
| known accounts' model and username must match the app's code, so they
| stay here.
|
*/

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
        'lifetime_minutes' => (int) env('AUTH_LOG_COOKIE_LIFETIME', 60 * 24 * 365 * 5),
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

    'retention_days' => (int) env('AUTH_LOG_RETENTION_DAYS', 365),

    /*
    |--------------------------------------------------------------------------
    | Activity
    |--------------------------------------------------------------------------
    |
    | How often a device's last-seen time, IP address and location are written
    | while it is in use.
    |
    */

    'activity_throttle_minutes' => (int) env('AUTH_LOG_ACTIVITY_THROTTLE', 5),

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

        'failed_attempts_threshold' => (int) env('AUTH_LOG_FAILED_ATTEMPTS_THRESHOLD', 5),
        'failed_attempts_window_minutes' => (int) env('AUTH_LOG_FAILED_ATTEMPTS_WINDOW', 60),
        'known_country_days' => (int) env('AUTH_LOG_KNOWN_COUNTRY_DAYS', 90),
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
        'code_lifetime_minutes' => (int) env('AUTH_LOG_CODE_LIFETIME', 15),
        'max_attempts' => (int) env('AUTH_LOG_CODE_MAX_ATTEMPTS', 5),
        'attempts_window_minutes' => (int) env('AUTH_LOG_CODE_ATTEMPTS_WINDOW', 60),
        'resend_cooldown_seconds' => (int) env('AUTH_LOG_CODE_RESEND_COOLDOWN', 60),
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

    /*
    |--------------------------------------------------------------------------
    | Known accounts
    |--------------------------------------------------------------------------
    |
    | The accounts that signed in on this browser, offered on the sign-in page
    | so the user can pick one instead of typing the email. At most `limit`
    | are listed, most recently used first. `model` keeps the list to one
    | authenticatable model, e.g. App\Models\User::class; null lists any.
    | `username` is the attribute shown masked and typed in the sign-in form.
    | AuthLog::knownAccountRoutes() redirects back to `login_route`.
    |
    */

    'known_accounts' => [
        'limit' => (int) env('AUTH_LOG_KNOWN_ACCOUNTS_LIMIT', 5),
        'model' => null,
        'username' => 'email',
        'login_route' => 'login',
    ],

];
