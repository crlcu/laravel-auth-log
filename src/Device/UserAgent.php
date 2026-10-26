<?php

namespace Kiddoflow\AuthLog\Device;

/**
 * Names the browser and platform in a User-Agent header, for people to
 * recognise their devices. Not used to tell devices apart.
 */
final readonly class UserAgent
{
    /**
     * Most browsers also carry the tokens of the engine they are built on
     * (Edge says "Chrome" and "Safari"), so the most specific come first.
     */
    private const BROWSERS = [
        'Edge' => '/\b(Edg|EdgA|EdgiOS|Edge)\//',
        'Opera' => '/\b(OPR|OPiOS)\/|\bOpera\b/',
        'Samsung Internet' => '/\bSamsungBrowser\//',
        'Firefox' => '/\b(Firefox|FxiOS)\//',
        'Chrome' => '/\b(Chrome|CriOS)\//',
        'Safari' => '/\bSafari\//',
    ];

    /**
     * iOS and iPadOS say "like Mac OS X" and Android says "Linux", so they come first.
     */
    private const PLATFORMS = [
        'iPhone' => '/\biPhone\b/',
        'iPad' => '/\biPad\b/',
        'Android' => '/\bAndroid\b/',
        'Windows' => '/\bWindows\b/',
        'ChromeOS' => '/\bCrOS\b/',
        'macOS' => '/\bMacintosh\b/',
        'Linux' => '/\bLinux\b/',
    ];

    public function __construct(
        public ?string $browser,
        public ?string $platform,
    ) {}

    public static function parse(?string $userAgent): self
    {
        return new self(
            browser: self::firstMatch(self::BROWSERS, (string) $userAgent),
            platform: self::firstMatch(self::PLATFORMS, (string) $userAgent),
        );
    }

    /**
     * @param  array<string, string>  $patterns
     */
    private static function firstMatch(array $patterns, string $userAgent): ?string
    {
        foreach ($patterns as $name => $pattern) {
            if (preg_match($pattern, $userAgent)) {
                return $name;
            }
        }

        return null;
    }
}
