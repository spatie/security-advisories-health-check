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

it('calls cache repository when caching is enabled', function () {
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
