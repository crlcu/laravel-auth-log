<?php

namespace Kiddoflow\AuthLog\Suspicion;

use Illuminate\Database\Eloquent\Model;
use Kiddoflow\AuthLog\Location\Location;

interface Rule
{
    /**
     * The reason the sign-in looks suspicious, or null when this rule finds nothing.
     * Runs before the sign-in itself is recorded.
     */
    public function check(Model $user, Location $location): ?string;
}
