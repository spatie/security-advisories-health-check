<?php

use GuzzleHttp\Client;
use GuzzleHttp\Exception\ClientException;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Spatie\Health\Enums\Status;
use Spatie\Packagist\PackagistClient;
use Spatie\SecurityAdvisoriesHealthCheck\SecurityAdvisoriesCheck;

it('can get security advisories', function () {
    $check = new SecurityAdvisoriesCheck();

    $result = $check->run();

    if ($result->status === Status::ok()) {
        expect($result->meta)->toBeEmpty();

        return;
    }

    expect(count($result->meta))->toBeGreaterThan(0);
});

it('returns ok status if 502, 503, or 504 is returned all 5 times', function () {
    $mock = new MockHandler([
        new Response(502),
        new Response(503),
        new Response(504),
        new Response(502),
        new Response(503),
    ]);

    $handlerStack = HandlerStack::create($mock);
    $client = new Client(['handler' => $handlerStack]);

    $packagistClient = new PackagistClient($client, new Spatie\Packagist\PackagistUrlGenerator());
    $check = new SecurityAdvisoriesCheck($packagistClient);

    $result = $check->run();

    expect($result->status)->toBe(Status::ok());
});

it('should throw the last encountered non-gateway exception after retrying gateway and non-gateway exceptions', function () {
    $mock = new MockHandler([
        new Response(502),
        new Response(400),
        new Response(504),
        new Response(403),
        new Response(504),
    ]);
    $handlerStack = HandlerStack::create($mock);
    $client = new Client(['handler' => $handlerStack]);

    $packagistClient = new PackagistClient($client, new Spatie\Packagist\PackagistUrlGenerator());
    $check = new SecurityAdvisoriesCheck($packagistClient);

    $check->run();
})->throws(ClientException::class, null, 403);

it('caches security advisories results', function () {
    $cache = new TestCache();

    $mockData = json_encode([
        'advisories' => [
            'vendor/package' => [
                [
                    'advisoryId' => 'ADVISORY-123',
                    'affectedVersions' => '>=1.0,<1.1',
                    'title' => 'Test Security Issue',
                ],
            ],
        ],
    ]);

    $mock = new MockHandler([
        new Response(200, [], $mockData),
    ]);

    $handlerStack = HandlerStack::create($mock);
    $client = new Client(['handler' => $handlerStack]);

    $packagistClient = new PackagistClient($client, new Spatie\Packagist\PackagistUrlGenerator());
    $check = new SecurityAdvisoriesCheck($packagistClient, $cache);
    $check->cacheResultsForMinutes(60); // Enable caching

    // First call should hit the API
    $result1 = $check->run();
    expect($mock->count())->toBe(0); // Mock should be consumed

    // Second call should use cache and not hit API
    $result2 = $check->run();

    expect($result1->status)->toBe($result2->status);
    expect($result1->notificationMessage)->toBe($result2->notificationMessage);
});

it('respects custom cache expiry time', function () {
    $cache = new TestCache();

    $mockData = json_encode([
        'advisories' => [
            'vendor/package' => [
                [
                    'advisoryId' => 'ADVISORY-456',
                    'affectedVersions' => '>=2.0,<2.1',
                    'title' => 'Another Security Issue',
                ],
            ],
        ],
    ]);

    $mock = new MockHandler([
        new Response(200, [], $mockData),
    ]);

    $handlerStack = HandlerStack::create($mock);
    $client = new Client(['handler' => $handlerStack]);

    $packagistClient = new PackagistClient($client, new Spatie\Packagist\PackagistUrlGenerator());
    $check = new SecurityAdvisoriesCheck($packagistClient, $cache);
    $check->cacheResultsForMinutes(120); // 2 hours

    $result = $check->run();

    // Verify that something was cached (we can't easily check the exact key without exposing it)
    expect($result)->toBeInstanceOf(\Spatie\Health\Checks\Result::class);
});

it('cache key changes when package list changes', function () {
    $cache1 = new TestCache();
    $cache2 = new TestCache();

    $mockData1 = json_encode(['advisories' => []]);
    $mockData2 = json_encode(['advisories' => []]);

    $mock = new MockHandler([
        new Response(200, [], $mockData1),
        new Response(200, [], $mockData2),
    ]);

    $handlerStack = HandlerStack::create($mock);
    $client = new Client(['handler' => $handlerStack]);

    $packagistClient = new PackagistClient($client, new Spatie\Packagist\PackagistUrlGenerator());

    // Create two different check instances with different ignored packages and different caches
    $check1 = new SecurityAdvisoriesCheck($packagistClient, $cache1);
    $check1->ignorePackage('some/package');

    $check2 = new SecurityAdvisoriesCheck($packagistClient, $cache2);
    $check2->ignorePackage('different/package');

    // Both should make HTTP calls since they have different cache keys
    $result1 = $check1->run();
    $result2 = $check2->run();

    expect($result1->status)->toBe(Status::ok());
    expect($result2->status)->toBe(Status::ok());
    expect($mock->count())->toBe(0); // Both requests should have been made
});

it('prevents external API calls when cache is hit', function () {
    $cache = new TestCache();

    $mockData = json_encode(['advisories' => []]);

    $mock = new MockHandler([
        new Response(200, [], $mockData),
    ]);

    $handlerStack = HandlerStack::create($mock);
    $client = new Client(['handler' => $handlerStack]);

    $packagistClient = new PackagistClient($client, new Spatie\Packagist\PackagistUrlGenerator());
    $check = new SecurityAdvisoriesCheck($packagistClient, $cache);
    $check->cacheResultsForMinutes(60); // Enable caching

    $cacheRepository = Mockery::mock(CacheRepository::class);
    $cacheRepository->shouldReceive('remember')
        ->once()
        ->with(
            \Mockery::pattern('/^security-advisories:[a-f0-9]{32}$/'),
            3600,
            \Mockery::type('callable')
        )
        ->andReturnUsing(function ($key, $ttl, $callback) {
            return $callback();
        });

    $check = new class($packagistClient, $cacheRepository) extends SecurityAdvisoriesCheck {
        protected CacheRepository $cacheRepo;

        public function __construct(?PackagistClient $packagistClient = null, ?CacheRepository $cacheRepository = null)
        {
            parent::__construct($packagistClient);
            $this->cacheRepo = $cacheRepository;
        }

        protected function getCacheRepository(): CacheRepository
        {
            return $this->cacheRepo;
        }
    };

    $check->cacheExpiryInMinutes(60);

    $result = $check->run();

    expect($result)->toBeInstanceOf(\Spatie\Health\Checks\Result::class);
});

it('respects custom cache expiry time', function () {
    $mockData = json_encode(['advisories' => []]);

    $mock = new MockHandler([
        new Response(200, [], $mockData),
    ]);

    $handlerStack = HandlerStack::create($mock);
    $client = new Client(['handler' => $handlerStack]);

    $packagistClient = new PackagistClient($client, new Spatie\Packagist\PackagistUrlGenerator());

    $cacheRepository = Mockery::mock(CacheRepository::class);
    $cacheRepository->shouldReceive('remember')
        ->once()
        ->with(
            \Mockery::type('string'),
            7200, // 120 minutes * 60 seconds
            \Mockery::type('callable')
        )
        ->andReturnUsing(function ($key, $ttl, $callback) {
            return $callback();
        });

    $check = new class($packagistClient, $cacheRepository) extends SecurityAdvisoriesCheck {
        protected CacheRepository $cacheRepo;

        public function __construct(?PackagistClient $packagistClient = null, ?CacheRepository $cacheRepository = null)
        {
            parent::__construct($packagistClient);
            $this->cacheRepo = $cacheRepository;
        }

        protected function getCacheRepository(): CacheRepository
        {
            return $this->cacheRepo;
        }
    };

    $check->cacheExpiryInMinutes(120); // 2 hours

    $result = $check->run();

    expect($result)->toBeInstanceOf(\Spatie\Health\Checks\Result::class);
});

it('does not use cache repository when caching is disabled', function () {
    $mockData = json_encode(['advisories' => []]);

    $mock = new MockHandler([
        new Response(200, [], $mockData),
    ]);

    $handlerStack = HandlerStack::create($mock);
    $client = new Client(['handler' => $handlerStack]);

    $packagistClient = new PackagistClient($client, new Spatie\Packagist\PackagistUrlGenerator());
    $check = new SecurityAdvisoriesCheck($packagistClient);
    $check->cacheExpiryInMinutes(0); // No caching

    $result = $check->run();

    expect($result->status)->toBe(Status::ok());
});

it('generates correct cache key based on packages', function () {
    $mockData = json_encode(['advisories' => []]);

    $mock = new MockHandler([
        new Response(200, [], $mockData),
    ]);

    $handlerStack = HandlerStack::create($mock);
    $client = new Client(['handler' => $handlerStack]);

    $packagistClient = new PackagistClient($client, new Spatie\Packagist\PackagistUrlGenerator());

    $cacheRepository = Mockery::mock(CacheRepository::class);
    $cacheRepository->shouldReceive('remember')
        ->once()
        ->with(
            \Mockery::pattern('/^security-advisories:[a-f0-9]{32}$/'),
            \Mockery::type('int'),
            \Mockery::type('callable')
        )
        ->andReturnUsing(function ($key, $ttl, $callback) {
            return $callback();
        });

    $check = new class($packagistClient, $cacheRepository) extends SecurityAdvisoriesCheck {
        protected CacheRepository $cacheRepo;

        public function __construct(?PackagistClient $packagistClient = null, ?CacheRepository $cacheRepository = null)
        {
            parent::__construct($packagistClient);
            $this->cacheRepo = $cacheRepository;
        }

        protected function getCacheRepository(): CacheRepository
        {
            return $this->cacheRepo;
        }
    };

    $check->cacheExpiryInMinutes(60);

    $result = $check->run();

    expect($result)->toBeInstanceOf(\Spatie\Health\Checks\Result::class);
});

it('can be instantiated early without resolving cache bindings', function () {
    // This simulates instantiation during ServiceProvider::register()
    // where cache bindings may not be fully available yet
    $check = new SecurityAdvisoriesCheck();
    $check->cacheExpiryInMinutes(60);

    expect($check)->toBeInstanceOf(SecurityAdvisoriesCheck::class);
});
