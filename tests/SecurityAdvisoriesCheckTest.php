<?php

use GuzzleHttp\Client;
use GuzzleHttp\Exception\ClientException;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
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
