<?php

namespace Crlcu\AuthLog\Location;

final readonly class Location
{
    /**
     * @param  string|null  $country  ISO 3166-1 alpha-2 code
     */
    public function __construct(
        public ?string $country = null,
        public ?string $city = null,
    ) {}
}
