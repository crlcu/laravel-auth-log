<?php

namespace Crlcu\AuthLog\KnownAccounts;

use Illuminate\Support\Collection;

/**
 * What the sign-in page shows: the list of accounts to choose from, one
 * chosen account to sign in to, or, when both are empty, the usual form.
 */
final readonly class LoginPage
{
    /**
     * @param  Collection<int, KnownAccount>  $accounts  the list to choose from, empty unless the list is shown
     * @param  bool  $hasOtherAccounts  whether changing the chosen account should go back to the list
     */
    public function __construct(
        public Collection $accounts,
        public ?KnownAccount $chosen,
        public bool $hasOtherAccounts,
    ) {}

    public function showsList(): bool
    {
        return $this->accounts->isNotEmpty();
    }

    public function showsForm(): bool
    {
        return $this->chosen === null && $this->accounts->isEmpty();
    }
}
