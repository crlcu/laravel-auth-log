<?php

namespace Crlcu\AuthLog\Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;
use Crlcu\AuthLog\Enums\AuthEventType;
use Crlcu\AuthLog\Models\AuthEvent;

/**
 * Attach an event to its user with ->for($user, 'authenticatable').
 *
 * @extends Factory<AuthEvent>
 */
class AuthEventFactory extends Factory
{
    protected $model = AuthEvent::class;

    public function definition(): array
    {
        return [
            'type' => AuthEventType::Login,
            'ip_address' => fake()->ipv4(),
            'user_agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36',
            'country' => 'RO',
            'city' => 'Cluj-Napoca',
            'created_at' => now(),
        ];
    }

    public function failed(): static
    {
        return $this->state(['type' => AuthEventType::Failed]);
    }

    /**
     * A sign-in from the given country.
     */
    public function fromCountry(string $country): static
    {
        return $this->state(['country' => $country, 'city' => null]);
    }
}
