<?php

namespace Spatie\SecurityAdvisoriesHealthCheck;

use Composer\InstalledVersions;
use GuzzleHttp\Client;
use Illuminate\Support\Collection;
use Spatie\Health\Checks\Check;
use Spatie\Health\Checks\Result;
use Spatie\Packagist\PackagistClient;
use Spatie\Packagist\PackagistUrlGenerator;

class SecurityAdvisoriesCheck extends Check
{
    public function run(): Result
    {
        $packages = $this->getInstalledPackages();

        $advisories = $this->getAdvisories($packages);

        if ($advisories->isEmpty()) {
            return Result::make('No security vulnerability advisories found');
        }

        $packageNames = $advisories->keys()
            ->map(fn(string $packageName) => "`{$packageName}`")
            ->join("'", ' and ');

        return Result::make()
            ->meta($advisories->toArray())
            ->failed("Security advisories found for {$packageNames}");
    }

    /**
     * @return Collection<string, string>
     */
    protected function getInstalledPackages(): Collection
    {
        return collect(InstalledVersions::getAllRawData()[0]['versions'])
            ->filter(fn(array $packageProperties) => isset($packageProperties['version']))
            ->mapWithKeys(function (array $packageProperties, string $package) {
                return [$package => $packageProperties['version']];
            });
    }

    /**
     * @return Collection<SecurityAdvisory>
     */
    protected function getAdvisories(Collection $packages): Collection
    {
        $advisories = $this
            ->getPackagist()
            ->getAdvisoriesAffectingVersions($packages->toArray());

        return collect($advisories);
    }

    protected function getPackagist(): PackagistClient
    {
        return new PackagistClient(
            new Client(),
            new PackagistUrlGenerator()
        );
    }
}
