<?php

namespace Crlcu\AuthLog;

use Closure;
use Crlcu\AuthLog\Http\Controllers\KnownAccountController;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

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

    /**
     * Register the routes the sign-in page's known accounts post to, to pick
     * one (`known-accounts.store`), ask for the usual form to sign in to
     * another (`known-accounts.another`) or forget one (`known-accounts.destroy`).
     * Call it inside the app's `web` routes.
     */
    public static function knownAccountRoutes(string $prefix = 'login/known-accounts'): void
    {
        Route::middleware('guest')->prefix($prefix)->name('known-accounts.')->group(function () {
            Route::post('/', [KnownAccountController::class, 'store'])->name('store');
            Route::post('another', [KnownAccountController::class, 'another'])->name('another');
            Route::delete('/', [KnownAccountController::class, 'destroy'])->name('destroy');
        });
    }
}
