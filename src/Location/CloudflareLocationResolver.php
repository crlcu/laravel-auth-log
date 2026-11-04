<?php

namespace Crlcu\AuthLog\Location;

use Illuminate\Http\Request;
use Illuminate\Support\Str;

/**
 * Reads the visitor's location from the headers Cloudflare adds: the country
 * always, the city when the "Add visitor location headers" managed transform
 * is on. No lookup and no database to keep up to date.
 *
 * Only trustworthy when every request reaches the app through Cloudflare.
 */
class CloudflareLocationResolver implements LocationResolver
{
    /**
     * Country codes Cloudflare uses for "unknown" and for Tor.
     */
    private const UNKNOWN_COUNTRIES = ['XX', 'T1'];

    public function resolve(Request $request): Location
    {
        $country = Str::upper((string) $request->header('CF-IPCountry'));
        $city = trim((string) $request->header('cf-ipcity'));

        return new Location(
            country: preg_match('/^[A-Z]{2}$/', $country) && ! in_array($country, self::UNKNOWN_COUNTRIES, true) ? $country : null,
            city: $city !== '' ? Str::limit($city, 100, '') : null,
        );
    }
}
