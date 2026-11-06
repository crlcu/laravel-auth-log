<?php

namespace Crlcu\AuthLog\Http\Controllers;

use Crlcu\AuthLog\KnownAccounts\Picker;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;

/**
 * Picks an account from the sign-in page's list, asks for the usual form to
 * sign in to another one, or takes one off the list on this browser.
 * Registered by AuthLog::knownAccountRoutes().
 */
class KnownAccountController extends Controller
{
    public function store(Request $request, Picker $picker): RedirectResponse
    {
        $picker->choose((string) $request->string('account'));

        return $this->toLogin();
    }

    public function another(Picker $picker): RedirectResponse
    {
        $picker->chooseAnother();

        return $this->toLogin();
    }

    public function destroy(Request $request, Picker $picker): RedirectResponse
    {
        $picker->forget((string) $request->string('account'));

        return $this->toLogin();
    }

    private function toLogin(): RedirectResponse
    {
        return redirect()->route(config('auth-log.known_accounts.login_route'));
    }
}
