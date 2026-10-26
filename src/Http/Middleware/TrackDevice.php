<?php

namespace Kiddoflow\AuthLog\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Kiddoflow\AuthLog\AuthLog;
use Kiddoflow\AuthLog\Tracker;
use Symfony\Component\HttpFoundation\Response;

/**
 * Ties each signed-in request to its device: signs out a device that was
 * signed out from elsewhere, holds a device back until it enters its emailed
 * code, and keeps the device's last-seen time current.
 */
class TrackDevice
{
    public function __construct(private Tracker $tracker) {}

    /**
     * @param  Closure(Request): (Response)  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        $user = $request->user();

        if (! Tracker::tracks($user) || AuthLog::ignores($request)) {
            $response = $next($request);

            $this->recordSessionOfNewSignIn($request);

            return $response;
        }

        $device = $this->tracker->currentDevice($user) ?? $this->tracker->adopt($user);

        if ($device->isSignedOut()) {
            $this->tracker->withoutTracking(fn () => Auth::guard()->logout());

            $request->session()->invalidate();
            $request->session()->regenerateToken();

            return redirect()->route(config('auth-log.signed_out_route'))
                ->with('status', __('You were signed out of this device.'));
        }

        if ($device->isAwaitingVerification() && ! $request->routeIs(config('auth-log.verification.allowed_routes'))) {
            return redirect()->route(config('auth-log.verification.route'));
        }

        $this->tracker->touch($device);

        return $next($request);
    }

    /**
     * Sign-in regenerates the session after the device is recorded (Fortify
     * and the social login both do), so the device is given its final
     * session id, which signing it out from elsewhere destroys.
     */
    private function recordSessionOfNewSignIn(Request $request): void
    {
        $user = $request->user();

        if (! Tracker::tracks($user) || AuthLog::ignores($request)) {
            return;
        }

        $device = $this->tracker->currentDevice($user);

        if ($device !== null && $device->session_id !== $request->session()->getId()) {
            $device->forceFill(['session_id' => $request->session()->getId()])->save();
        }
    }
}
