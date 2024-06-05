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
use Throwable;

class SecurityAdvisoriesCheck extends Check
{
    /** @var array<string> */
    protected array $ignoredPackages = [];

    protected int $retryTimes = 5;

    protected int $gatewayExceptionCount = 0;

    protected ?Throwable $lastNonGatewayException = null;

    public PackagistClient $packagistClient;

    public function __construct(?PackagistClient $packagistClient = null)
    {
        parent::__construct();

        $this->packagistClient = $packagistClient
            ?? new PackagistClient(new Client(), new PackagistUrlGenerator());
    }

    public function retryTimes(int $times): self
    {
        $this->retryTimes = $times;

        return $this;
    }

    /**
     * @throws Throwable
     */
    public function run(): Result
    {
        $packages = $this->getInstalledPackages();

        try {
            $advisories = $this->retryGetAdvisories($packages);
        } catch (Throwable $exception) {
            if ($this->allRetriesAreGatewayErrors()) {
                return Result::make('Packagist service could not be reached')->ok();
            }

            throw $this->lastNonGatewayException ?? $exception;
        }

        if ($advisories->isEmpty()) {
            return Result::make('No security vulnerability advisories found')->ok();
        }

        $packageNames = $advisories->keys()
            ->map(fn (string $packageName) => "`{$packageName}`")
            ->join(', ', ' and ');

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
            ->packagistClient
            ->getAdvisoriesAffectingVersions($packages->toArray());

        return collect($advisories);
    }

    protected function allRetriesAreGatewayErrors(): bool
    {
        // Compare `$this->gatewayExceptionCount` with `retryTimes - 1` rather than `retryTimes`.
        // The `shouldRetry` callback is not executed on the final retry, so the last exception
        // in the retry loop does not increment `$this->gatewayExceptionCount`.

        return $this->gatewayExceptionCount === $this->retryTimes - 1;
    }

    /**
     * @throws Throwable
     */
    protected function retryGetAdvisories(Collection $packages): Collection
    {
        return retry(
            times: $this->retryTimes,
            callback: fn () => $this->getAdvisories($packages),
            sleepMilliseconds: 2 * 1000,
            when: fn ($exception) => $this->shouldRetry($exception)
        );
    }

    protected function shouldRetry($exception): bool
    {
        $isGatewayException = $exception instanceof ServerException
            && in_array($exception->getCode(), [502, 503, 504]);

        if ($isGatewayException) {
            $this->gatewayExceptionCount++;
        }

        $this->lastNonGatewayException = $isGatewayException
            ? $this->lastNonGatewayException
            : $exception;

        return true;
    }
}
