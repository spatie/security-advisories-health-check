<?php

namespace Spatie\SecurityAdvisoriesHealthCheck;

use Composer\InstalledVersions;
use GuzzleHttp\Client;
use Hammerstone\Flaky\Flaky;
use Illuminate\Support\Collection;
use Spatie\Health\Checks\Check;
use Spatie\Health\Checks\Result;
use Spatie\Packagist\PackagistClient;
use Spatie\Packagist\PackagistUrlGenerator;

class SecurityAdvisoriesCheck extends Check
{
    /** @var array<string> */
    protected array $ignoredPackages = [];

    public function run(): Result
    {
        $packages = $this->getInstalledPackages();

        $advisories = $this->getAdvisories($packages);

        if ($advisories->isEmpty()) {
            return Result::make('No security vulnerability advisories found')->ok();
        }

        $packageNames = $advisories->keys()
            ->map(fn (string $packageName) => "`{$packageName}`")
            ->join(", ", ' and ');

        return Result::make()
            ->meta($advisories->toArray())
            ->failed("Security advisories found for {$packageNames}");
    }

    public function ignorePackage(string $packageName): self
    {
        $this->ignoredPackages[] = $packageName;

        return $this;
    }

    public function ignoredPackages(array $packageNames): self
    {
        foreach ($packageNames as $packageName) {
            $this->ignorePackage($packageName);
        }

        return $this;
    }

    /**
     * @return Collection<string, string>
     */
    protected function getInstalledPackages(): Collection
    {
        return collect(InstalledVersions::getAllRawData()[0]['versions'])
            ->filter(fn (array $packageProperties) => isset($packageProperties['version']))
            ->filter(fn (array $packageProperties, string $packageName) => ! in_array($packageName, $this->ignoredPackages))
            ->mapWithKeys(function (array $packageProperties, string $packageName) {
                return [$packageName => $packageProperties['version']];
            });
    }

    /**
     * @return Collection<string>
     */
    protected function getAdvisories(Collection $packages): Collection
    {
        $advisories = Flaky::make('health-check-retrieve-packagist-advisories')
            ->allowFailuresForAnHour()
            ->run(function() use ($packages) {
                return $this
                    ->getPackagist()
                    ->getAdvisoriesAffectingVersions($packages->toArray());
            });

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
