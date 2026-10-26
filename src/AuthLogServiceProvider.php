<?php

namespace Kiddoflow\AuthLog;

use Illuminate\Auth\AuthManager;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\ServiceProvider;
use Kiddoflow\AuthLog\Guard\TrackedSessionGuard;
use Kiddoflow\AuthLog\Listeners\RecordAuthEvents;
use Kiddoflow\AuthLog\Location\LocationResolver;

class AuthLogServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/auth-log.php', 'auth-log');

        $this->app->scoped(Tracker::class);
        $this->app->bind(LocationResolver::class, fn (Application $app) => $app->make(config('auth-log.location_resolver')));
    }

    public function boot(): void
    {
        $this->loadMigrationsFrom(__DIR__.'/../database/migrations');

        $this->publishes([__DIR__.'/../config/auth-log.php' => config_path('auth-log.php')], 'auth-log-config');

        $this->registerGuard();

        Event::subscribe(RecordAuthEvents::class);
    }

    /**
     * The "tracked-session" guard driver: Laravel's session guard, built the
     * same way, with device tracking on top.
     */
    private function registerGuard(): void
    {
        $this->app->make(AuthManager::class)->extend('tracked-session', function (Application $app, string $name, array $config) {
            $auth = $app->make(AuthManager::class);

            $guard = new TrackedSessionGuard(
                $name,
                $auth->createUserProvider($config['provider'] ?? null),
                $app['session.store'],
                rehashOnLogin: $app['config']->get('hashing.rehash_on_login', true),
                timeboxDuration: $app['config']->get('auth.timebox_duration', 200000),
                hashKey: $app['config']->get('app.key'),
            );

            $guard->setCookieJar($app['cookie']);
            $guard->setDispatcher($app['events']);
            $guard->setRequest($app->refresh('request', $guard, 'setRequest'));

            if (isset($config['remember'])) {
                $guard->setRememberDuration($config['remember']);
            }

            return $guard;
        });
    }
}
