<?php

namespace Spatie\SecurityAdvisoriesHealthCheck;

use Composer\InstalledVersions;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\ServerException;
use Illuminate\Support\Collection;
use Spatie\Health\Checks\Check;
use Spatie\Health\Checks\Result;
use Spatie\Packagist\PackagistClient;
use Spatie\Packagist\PackagistUrlGenerator;

class SecurityAdvisoriesCheck extends Check
{
    /** @var array<string> */
    protected array $ignoredPackages = [];

    protected int $retryTimes = 5;

    public function retryTimes(int $times): self
    {
        $this->retryTimes = $times;

        return $this;
    }

    public function run(): Result
    {
        $packages = $this->getInstalledPackages();

        $packagistGatewayErrorCount = 0;

        try {
            $advisories = retry(
                times: $this->retryTimes,
                callback: function () use ($packages) {
                    return $this->getAdvisories($packages);
                },
                sleepMilliseconds: 2 * 1000,
                when: function ($e) use (&$packagistGatewayErrorCount) {
                    if ($e instanceof ServerException && in_array($e->getCode(), [502, 503, 504])) {
                        $packagistGatewayErrorCount++;
                    }

                    return true;
                }
            );
        } catch (ServerException $e) {
            if ($packagistGatewayErrorCount === $this->retryTimes) {
                return Result::make('Packagist service could not be reached')->ok();
            }

            throw $e;
        }

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
