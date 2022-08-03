<?php

use Spatie\SecurityAdvisoriesHealthCheck\SecurityAdvisoriesCheck;

it('can get security advisories', function () {
    $check = new SecurityAdvisoriesCheck();

    $result = $check->run();

    if ($result->ok()) {
        expect($result->meta)->toBeEmpty();
    }

    if (! $result->ok()) {
        expect(count($result->meta))->toBeGreaterThan(0);
    }
});
