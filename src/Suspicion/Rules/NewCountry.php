<?php

namespace Kiddoflow\AuthLog\Suspicion\Rules;

use Illuminate\Database\Eloquent\Model;
use Kiddoflow\AuthLog\Enums\AuthEventType;
use Kiddoflow\AuthLog\Location\Location;
use Kiddoflow\AuthLog\Models\AuthEvent;
use Kiddoflow\AuthLog\Suspicion\Rule;

/**
 * A sign-in from a country the user has not signed in from recently. Users
 * with no recent sign-in from a known country are not flagged, so the first
 * sign-in after joining, or after a long break, goes through.
 */
class NewCountry implements Rule
{
    public const REASON = 'new_country';

    public function check(Model $user, Location $location): ?string
    {
        if ($location->country === null) {
            return null;
        }

        $knownCountries = AuthEvent::query()
            ->forAuthenticatable($user)
            ->where('type', AuthEventType::Login)
            ->whereNotNull('country')
            ->where('created_at', '>=', now()->subDays((int) config('auth-log.suspicion.known_country_days')))
            ->distinct()
            ->pluck('country');

        return $knownCountries->isNotEmpty() && ! $knownCountries->contains($location->country) ? self::REASON : null;
    }
}
