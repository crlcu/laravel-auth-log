<?php

namespace Crlcu\AuthLog\KnownAccounts;

use Crlcu\AuthLog\Models\Device;
use Crlcu\AuthLog\Tracker;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Session\Store;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Crypt;

/**
 * The accounts that signed in on this browser, offered on the sign-in page so
 * people pick one instead of typing their email. Only accounts known to this
 * browser's device cookie are ever found, listed or forgotten, and only
 * models of `auth-log.known_accounts.model` when it is set.
 */
class Picker
{
    /**
     * Session key holding, for the next page only, the account just picked.
     */
    public const CHOSEN_SESSION_KEY = 'auth_log_known_account';

    /**
     * Session key asking, for the next page only, for the usual form instead.
     */
    public const ANOTHER_ACCOUNT_SESSION_KEY = 'auth_log_another_account';

    public function __construct(private Tracker $tracker, private Store $session) {}

    /**
     * Most recently used first.
     *
     * @return Collection<int, KnownAccount>
     */
    public function all(): Collection
    {
        return $this->tracker->knownAccounts($this->model())
            ->map(fn (Device $device) => new KnownAccount($device))
            ->toBase();
    }

    public function find(string $reference): ?KnownAccount
    {
        $deviceKey = $this->deviceKey($reference);

        return $deviceKey !== null ? $this->findByDeviceKey($deviceKey) : null;
    }

    /**
     * Pick the account for the next page, which then asks for its password.
     * Nothing goes in the address, so device ids never show there.
     */
    public function choose(string $reference): bool
    {
        $account = $this->find($reference);

        if ($account === null) {
            return false;
        }

        $this->session->flash(self::CHOSEN_SESSION_KEY, $account->deviceKey());

        return true;
    }

    /**
     * Show the usual form on the next page, to sign in to an account that is
     * not offered, without anything in the address.
     */
    public function chooseAnother(): void
    {
        $this->session->flash(self::ANOTHER_ACCOUNT_SESSION_KEY, true);
    }

    /**
     * Stop offering the account on this browser. Signing in again brings it back.
     */
    public function forget(string $reference): bool
    {
        $deviceKey = $this->deviceKey($reference);

        return $deviceKey !== null && $this->tracker->forgetKnownAccount($deviceKey);
    }

    /**
     * An account is chosen right after it is picked from the list, when it
     * is the only one this browser knows, or when its password was just
     * mistyped. The usual form is shown when asked for another account, when
     * none is known, or after a failed sign-in with an email typed by hand.
     */
    public function forLoginPage(): LoginPage
    {
        if ($this->session->get(self::ANOTHER_ACCOUNT_SESSION_KEY)) {
            return new LoginPage(new Collection, null, false);
        }

        $accounts = $this->all();
        $typedEmail = $this->session->getOldInput(config('auth-log.known_accounts.username'));
        $pickedKey = $this->session->get(self::CHOSEN_SESSION_KEY);

        $chosen = match (true) {
            $pickedKey !== null => $this->findByDeviceKey($pickedKey),
            $typedEmail !== null => $accounts->first(fn (KnownAccount $account): bool => $account->email() === $typedEmail),
            $accounts->count() === 1 => $accounts->first(),
            default => null,
        };

        $showsList = $chosen === null && $typedEmail === null && $accounts->count() > 1;

        return new LoginPage($showsList ? $accounts : new Collection, $chosen, $accounts->count() > 1);
    }

    private function findByDeviceKey(int|string $deviceKey): ?KnownAccount
    {
        $device = $this->tracker->knownAccount($deviceKey, $this->model());

        return $device !== null ? new KnownAccount($device) : null;
    }

    private function deviceKey(string $reference): ?string
    {
        try {
            return Crypt::decryptString($reference);
        } catch (DecryptException) {
            return null;
        }
    }

    /**
     * @return class-string<Model>|null
     */
    private function model(): ?string
    {
        return config('auth-log.known_accounts.model');
    }
}
