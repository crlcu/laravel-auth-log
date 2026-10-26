<?php

namespace Kiddoflow\AuthLog\Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Support\Str;
use Kiddoflow\AuthLog\Models\Device;

/**
 * Attach a device to its owner with ->for($user, 'authenticatable').
 *
 * @extends Factory<Device>
 */
class DeviceFactory extends Factory
{
    protected $model = Device::class;

    public function definition(): array
    {
        return [
            'device_token_hash' => hash('sha256', Str::random(40)),
            'session_id' => Str::random(40),
            'browser' => 'Chrome',
            'platform' => 'Windows',
            'ip_address' => fake()->ipv4(),
            'country' => 'RO',
            'city' => 'Cluj-Napoca',
            'first_seen_at' => now()->subMonth(),
            'last_seen_at' => now(),
            'verified_at' => now()->subMonth(),
        ];
    }

    /**
     * A device whose browser holds this device cookie value.
     */
    public function withDeviceToken(string $deviceToken): static
    {
        return $this->state(['device_token_hash' => hash('sha256', $deviceToken)]);
    }

    public function signedOut(): static
    {
        return $this->state(['signed_out_at' => now(), 'session_id' => null, 'remember_token_hash' => null]);
    }
}
