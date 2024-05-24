# A Laravel Health check to security advisories for PHP packages

[![Latest Version on Packagist](https://img.shields.io/packagist/v/spatie/security-advisories-health-check.svg?style=flat-square)](https://packagist.org/packages/spatie/security-advisories-health-check)
[![Total Downloads](https://img.shields.io/packagist/dt/spatie/security-advisories-health-check.svg?style=flat-square)](https://packagist.org/packages/spatie/security-advisories-health-check)

This package contains a [Laravel Health](https://spatie.be/docs/laravel-health) check that can report any known security issues with the installed PHP packages in your application.

The security advisories are fetched from Packages and are sources from GitHub, and other sources.

```php
// typically, in a service provider

use Spatie\Health\Facades\Health;
use Spatie\SecurityAdvisoriesHealthCheck\SecurityAdvisoriesCheck;

Health::checks([
    SecurityAdvisoriesCheck::new()->retryTimes(5),
]);
```

## Documentation

The documentation of this package is available [inside the docs of Laravel Health](https://spatie.be/docs/laravel-health/v1/available-checks/security-advisories).

## Support us

[<img src="https://github-ads.s3.eu-central-1.amazonaws.com/security-advisories-health-check.jpg?t=1" width="419px" />](https://spatie.be/github-ad-click/security-advisories-health-check)

We invest a lot of resources into creating [best in class open source packages](https://spatie.be/open-source). You can support us by [buying one of our paid products](https://spatie.be/open-source/support-us).

We highly appreciate you sending us a postcard from your hometown, mentioning which of our package(s) you are using. You'll find our address on [our contact page](https://spatie.be/about-us). We publish all received postcards on [our virtual postcard wall](https://spatie.be/open-source/postcards).

## Testing

```bash
composer test
```

## Changelog

Please see [CHANGELOG](CHANGELOG.md) for more information on what has changed recently.

## Contributing

Please see [CONTRIBUTING](https://github.com/spatie/.github/blob/main/CONTRIBUTING.md) for details.

## Security Vulnerabilities

Please review [our security policy](../../security/policy) on how to report security vulnerabilities.

## Credits

- [Freek Van der Herten](https://github.com/freekmurze)
- [All Contributors](../../contributors)

## License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information.
