<?php

namespace Crlcu\AuthLog\Location;

use Illuminate\Http\Request;

interface LocationResolver
{
    public function resolve(Request $request): Location;
}
