<?php

namespace Spatie\SecurityAdvisoriesHealthCheck;

use Composer\InstalledVersions;
use GuzzleHttp\Client;
use Spatie\Health\Checks\Check;
use Spatie\Health\Checks\Result;
use Spatie\Packagist\PackagistClient;
use Spatie\Packagist\PackagistUrlGenerator;

class SecurityAdvisoriesCheck extends Check
{
    public function run(): Result
    {
        $packages = $this->getInstalledPackages();

        $advisories = $this
            ->getPackagist()
            ->getAdvisoriesAffectingVersions($packages);

        if (count($advisories) === 0) {
            return Result::make('No security vulnerability advisories found');
        }

        Result::make();

        dd($advisories);
    }

    /**
     * @return array<string, string>
     */
    protected function getInstalledPackages(): array
    {
        return collect(InstalledVersions::getAllRawData()[0]['versions'])
            ->filter(fn (array $packageProperties) => isset($packageProperties['version']))
            ->mapWithKeys(function (array $packageProperties, string $package) {
                return [$package => $packageProperties['version']];
            })
            ->toArray();
    }

    protected function getPackagist(): PackagistClient
    {
        return new PackagistClient(
            new Client(),
            new PackagistUrlGenerator()
        );
    }
}
