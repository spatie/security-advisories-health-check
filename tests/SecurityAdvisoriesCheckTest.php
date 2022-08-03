<?php

use Spatie\SecurityAdvisoriesHealthCheck\SecurityAdvisoriesCheck;

it('can get security advisories', function () {
    $check = new SecurityAdvisoriesCheck();

    dd($check->run());
});
