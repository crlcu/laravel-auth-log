<?php

namespace Kiddoflow\AuthLog;

use Closure;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;

/**
 * App-wide settings made once at boot, in a service provider. They hold no
 * per-request state, so they are safe to keep statically under Octane.
 */
final class AuthLog
{
    /**
     * @var (Closure(Request): bool)|null
     */
    private static ?Closure $ignoreRequestsUsing = null;

    /**
     * @var (Closure(Model): bool)|null
     */
    private static ?Closure $skipVerificationUsing = null;

    /**
     * Leave requests alone that are not the user acting for themselves, such
     * as an admin masquerading as them: their device is not checked or touched.
     *
     * @param  (Closure(Request): bool)|null  $callback
     */
    public static function ignoreRequestsUsing(?Closure $callback): void
    {
        self::$ignoreRequestsUsing = $callback;
    }

    public static function ignores(Request $request): bool
    {
        return self::$ignoreRequestsUsing !== null && (self::$ignoreRequestsUsing)($request);
    }

    /**
     * Skip the emailed code for users who already passed another check at
     * sign-in, such as two-factor. Their flagged sign-ins are still recorded.
     *
     * @param  (Closure(Model): bool)|null  $callback
     */
    public static function skipVerificationWhen(?Closure $callback): void
    {
        self::$skipVerificationUsing = $callback;
    }

    public static function skipsVerificationFor(Model $user): bool
    {
        return self::$skipVerificationUsing !== null && (self::$skipVerificationUsing)($user);
    }
}
