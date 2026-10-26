<?php

namespace Kiddoflow\AuthLog\Suspicion;

use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Model;
use Kiddoflow\AuthLog\Location\Location;

class Detector
{
    public function __construct(private Container $container) {}

    /**
     * The reasons the configured rules found to distrust this sign-in.
     *
     * @return list<string>
     */
    public function detect(Model $user, Location $location): array
    {
        $reasons = [];

        foreach (config('auth-log.suspicion.rules', []) as $rule) {
            /** @var Rule $rule */
            $rule = $this->container->make($rule);

            if ($reason = $rule->check($user, $location)) {
                $reasons[] = $reason;
            }
        }

        return $reasons;
    }
}
