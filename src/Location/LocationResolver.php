<?php

namespace Kiddoflow\AuthLog\Location;

use Illuminate\Http\Request;

interface LocationResolver
{
    public function resolve(Request $request): Location;
}
