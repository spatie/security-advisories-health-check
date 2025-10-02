<?php

use GuzzleHttp\Client;
use GuzzleHttp\Exception\ClientException;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Mockery;
use Spatie\Health\Checks\Result;
use Spatie\Health\Enums\Status;
use Spatie\Packagist\PackagistClient;
use Spatie\Packagist\PackagistUrlGenerator;
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

    $packagistClient = new PackagistClient($client, new PackagistUrlGenerator());
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

    $packagistClient = new PackagistClient($client, new PackagistUrlGenerator());
    $check = new SecurityAdvisoriesCheck($packagistClient);

    $check->run();
})->throws(ClientException::class, null, 403);

it('uses Laravel cache when caching is enabled', function () {
    $mockData = json_encode(['advisories' => []]);

    $mock = new MockHandler([
        new Response(200, [], $mockData),
    ]);

    $handlerStack = HandlerStack::create($mock);
    $client = new Client(['handler' => $handlerStack]);

    $packagistClient = new PackagistClient($client, new PackagistUrlGenerator());

    // Mock the cache repository
    $cacheRepository = Mockery::mock(CacheRepository::class);
    $cacheRepository->shouldReceive('remember')
        ->once()
        ->with(
            Mockery::pattern('/^security-advisories:[a-f0-9]{32}$/'),
            3600, // 60 minutes * 60 seconds
            Mockery::type('callable')
        )
        ->andReturnUsing(function ($key, $ttl, $callback) {
            return $callback();
        });

    // Mock App::make to return our mock cache
    $app = Mockery::mock('alias:Illuminate\Support\Facades\App');
    $app->shouldReceive('make')
        ->with('cache.store')
        ->andReturn($cacheRepository);

    $check = new SecurityAdvisoriesCheck($packagistClient);
    $check->cacheResultsForMinutes(60);

    $result = $check->run();

    expect($result)->toBeInstanceOf(Result::class);
    expect($result->status)->toBe(Status::ok());
});

it('cache is called multiple times when cache stores result', function () {
    $mockData = json_encode(['advisories' => []]);

    $mock = new MockHandler([
        new Response(200, [], $mockData),
    ]);

    $handlerStack = HandlerStack::create($mock);
    $client = new Client(['handler' => $handlerStack]);

    $packagistClient = new PackagistClient($client, new PackagistUrlGenerator());

    // Mock cache that stores and returns values
    $cachedValue = null;
    $cacheRepository = Mockery::mock(CacheRepository::class);
    $cacheRepository->shouldReceive('remember')
        ->twice() // Should be called twice
        ->with(
            Mockery::pattern('/^security-advisories:[a-f0-9]{32}$/'),
            3600,
            Mockery::type('callable')
        )
        ->andReturnUsing(function ($key, $ttl, $callback) use (&$cachedValue) {
            if ($cachedValue === null) {
                $cachedValue = $callback(); // First call: execute callback
            }

            return $cachedValue; // Return cached value
        });

    // Mock App::make to return our mock cache
    $app = Mockery::mock('alias:Illuminate\Support\Facades\App');
    $app->shouldReceive('make')
        ->with('cache.store')
        ->andReturn($cacheRepository);

    $check = new SecurityAdvisoriesCheck($packagistClient);
    $check->cacheResultsForMinutes(60);

    // First call should hit the API
    $result1 = $check->run();
    expect($mock->count())->toBe(0); // Mock should be consumed

    // Second call should use cache and not hit API
    $result2 = $check->run();
    expect($mock->count())->toBe(0);

    expect($result1->status)->toBe($result2->status);
});

it('does not use cache when caching is disabled', function () {
    $mockData = json_encode(['advisories' => []]);

    $mock = new MockHandler([
        new Response(200, [], $mockData),
        new Response(200, [], $mockData),
    ]);

    $handlerStack = HandlerStack::create($mock);
    $client = new Client(['handler' => $handlerStack]);

    $packagistClient = new PackagistClient($client, new PackagistUrlGenerator());
    $check = new SecurityAdvisoriesCheck($packagistClient);
    $check->cacheResultsForMinutes(0); // No caching

    // First call
    $result1 = $check->run();
    expect($result1->status)->toBe(Status::ok());

    // Second call should hit API again (not use cache)
    $result2 = $check->run();
    expect($result2->status)->toBe(Status::ok());

    // Both requests should have been made
    expect($mock->count())->toBe(0); // All mocks consumed = 2 API calls made
});


it('can be instantiated early without resolving cache bindings', function () {
    // This simulates instantiation during ServiceProvider::register()
    // where cache bindings may not be fully available yet
    $check = new SecurityAdvisoriesCheck();
    $check->cacheResultsForMinutes(60);

    expect($check)->toBeInstanceOf(SecurityAdvisoriesCheck::class);
});

it('works when instantiated in register() without caching enabled', function () {
    // Simulates: SecurityAdvisoriesCheck::new() in ServiceProvider::register()
    // without any caching - should work immediately
    $mockData = json_encode(['advisories' => []]);

    $mock = new MockHandler([
        new Response(200, [], $mockData),
    ]);

    $handlerStack = HandlerStack::create($mock);
    $client = new Client(['handler' => $handlerStack]);

    $packagistClient = new PackagistClient($client, new PackagistUrlGenerator());
    $check = new SecurityAdvisoriesCheck($packagistClient);
    // Note: No caching enabled (cacheResultsForMinutes not called)

    $result = $check->run();

    expect($result->status)->toBe(Status::ok());
});


it('works when instantiated in boot() without caching', function () {
    // Simulates: SecurityAdvisoriesCheck::new() in ServiceProvider::boot()
    // Same as register() - should work identically
    $mockData = json_encode(['advisories' => []]);

    $mock = new MockHandler([
        new Response(200, [], $mockData),
    ]);

    $handlerStack = HandlerStack::create($mock);
    $client = new Client(['handler' => $handlerStack]);

    $packagistClient = new PackagistClient($client, new PackagistUrlGenerator());
    $check = new SecurityAdvisoriesCheck($packagistClient);

    $result = $check->run();

    expect($result->status)->toBe(Status::ok());
});
