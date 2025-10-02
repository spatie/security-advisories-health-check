<?php

use GuzzleHttp\Client;
use GuzzleHttp\Exception\ClientException;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use Spatie\Health\Checks\Result;
use Spatie\Health\Enums\Status;
use Spatie\Packagist\PackagistClient;
use Spatie\Packagist\PackagistUrlGenerator;
use Spatie\SecurityAdvisoriesHealthCheck\SecurityAdvisoriesCheck;
use Spatie\SecurityAdvisoriesHealthCheck\Tests\TestCache;

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

    $packagistClient = new PackagistClient($client, new PackagistUrlGenerator());
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
    $mockData = json_encode(['advisories' => []]);

    $mock = new MockHandler([
        new Response(200, [], $mockData),
    ]);

    $handlerStack = HandlerStack::create($mock);
    $client = new Client(['handler' => $handlerStack]);

    $packagistClient = new PackagistClient($client, new PackagistUrlGenerator());
    $check = new SecurityAdvisoriesCheck($packagistClient, $cache);
    $check->cacheResultsForMinutes(120); // 2 hours

    $result = $check->run();

    expect($result)->toBeInstanceOf(Result::class);
});

it('does not use cache when caching is disabled', function () {
    $mockData = json_encode(['advisories' => []]);

    $mock = new MockHandler([
        new Response(200, [], $mockData),
    ]);

    $handlerStack = HandlerStack::create($mock);
    $client = new Client(['handler' => $handlerStack]);

    $packagistClient = new PackagistClient($client, new PackagistUrlGenerator());
    $check = new SecurityAdvisoriesCheck($packagistClient);
    $check->cacheResultsForMinutes(0); // No caching

    $result = $check->run();

    expect($result->status)->toBe(Status::ok());
});

it('uses cache when enabled', function () {
    $cache = new TestCache();
    $mockData = json_encode(['advisories' => []]);

    $mock = new MockHandler([
        new Response(200, [], $mockData),
    ]);

    $handlerStack = HandlerStack::create($mock);
    $client = new Client(['handler' => $handlerStack]);

    $packagistClient = new PackagistClient($client, new PackagistUrlGenerator());
    $check = new SecurityAdvisoriesCheck($packagistClient, $cache);
    $check->cacheResultsForMinutes(60);

    // First call should hit the API
    $result1 = $check->run();
    expect($mock->count())->toBe(0); // Mock should be consumed

    // Second call should use cache and not hit API
    $result2 = $check->run();

    expect($result1)->toBeInstanceOf(Result::class);
    expect($result2)->toBeInstanceOf(Result::class);
    expect($result1->status)->toBe($result2->status);
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

it('works when instantiated in register() with PSR-16 cache', function () {
    // Simulates: new SecurityAdvisoriesCheck(null, $cache) in ServiceProvider::register()
    // with PSR-16 cache - should work because it doesn't need Laravel cache
    $cache = new TestCache();
    $mockData = json_encode(['advisories' => []]);

    $mock = new MockHandler([
        new Response(200, [], $mockData),
        new Response(200, [], $mockData),
    ]);

    $handlerStack = HandlerStack::create($mock);
    $client = new Client(['handler' => $handlerStack]);

    $packagistClient = new PackagistClient($client, new PackagistUrlGenerator());
    $check = new SecurityAdvisoriesCheck($packagistClient, $cache);
    $check->cacheResultsForMinutes(60);

    // First call
    $result1 = $check->run();
    expect($result1->status)->toBe(Status::ok());

    // Second call should use cache
    $result2 = $check->run();
    expect($result2->status)->toBe(Status::ok());
    expect($mock->count())->toBe(1); // Only one request should have been made
});

// Note: Testing with Laravel's cache facade requires a full Laravel application
// In real usage:
// - register() + cacheResultsForMinutes() works because cache resolution is lazy (happens in run())
// - boot() + cacheResultsForMinutes() also works as the cache facade is available
// Both scenarios work identically - the cache is only resolved when run() is called

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
