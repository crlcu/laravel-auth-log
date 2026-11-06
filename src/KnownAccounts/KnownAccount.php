<?php

namespace Crlcu\AuthLog\KnownAccounts;

use Carbon\CarbonInterface;
use Crlcu\AuthLog\Models\Device;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Str;

/**
 * An account that signed in on this browser, as offered on the sign-in page.
 * The device behind it stays inside the package: pages and forms only ever
 * get its encrypted reference, never the device id.
 */
final class KnownAccount
{
    public function __construct(private Device $device) {}

    /**
     * What the page's forms send to pick or forget this account.
     */
    public function reference(): string
    {
        return Crypt::encryptString((string) $this->device->getKey());
    }

    public function authenticatable(): Model
    {
        return $this->device->authenticatable;
    }

    public function email(): string
    {
        return (string) $this->authenticatable()->getAttribute(config('auth-log.known_accounts.username'));
    }

    /**
     * Enough of the email to tell accounts apart, like "an****@gmail.com".
     */
    public function maskedEmail(): string
    {
        [$local, $domain] = array_pad(explode('@', $this->email(), 2), 2, '');

        $visible = Str::substr($local, 0, Str::length($local) > 2 ? 2 : 1);

        return $visible.'****@'.$domain;
    }

    public function lastUsedAt(): CarbonInterface
    {
        return $this->device->last_seen_at;
    }

    /**
     * @internal
     */
    public function deviceKey(): int|string
    {
        return $this->device->getKey();
    }
}
