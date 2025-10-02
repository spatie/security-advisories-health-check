<?php

namespace Spatie\SecurityAdvisoriesHealthCheck\Tests;

use Psr\SimpleCache\CacheInterface;

class TestCache implements CacheInterface
{
    private array $cache = [];
    private array $expiry = [];

    public function get(string $key, mixed $default = null): mixed
    {
        $this->checkExpiry($key);

        return $this->cache[$key] ?? $default;
    }

    public function set(string $key, mixed $value, null|int|\DateInterval $ttl = null): bool
    {
        $this->cache[$key] = $value;

        if ($ttl !== null) {
            $expiryTime = is_int($ttl)
                ? time() + $ttl
                : time() + $ttl->totalSeconds;
            $this->expiry[$key] = $expiryTime;
        }

        return true;
    }

    public function delete(string $key): bool
    {
        unset($this->cache[$key], $this->expiry[$key]);

        return true;
    }

    public function clear(): bool
    {
        $this->cache = [];
        $this->expiry = [];

        return true;
    }

    public function getMultiple(iterable $keys, mixed $default = null): iterable
    {
        $result = [];
        foreach ($keys as $key) {
            $result[$key] = $this->get($key, $default);
        }

        return $result;
    }

    public function setMultiple(iterable $values, null|int|\DateInterval $ttl = null): bool
    {
        foreach ($values as $key => $value) {
            $this->set($key, $value, $ttl);
        }

        return true;
    }

    public function deleteMultiple(iterable $keys): bool
    {
        foreach ($keys as $key) {
            $this->delete($key);
        }

        return true;
    }

    public function has(string $key): bool
    {
        $this->checkExpiry($key);

        return array_key_exists($key, $this->cache);
    }

    private function checkExpiry(string $key): void
    {
        if (isset($this->expiry[$key]) && time() > $this->expiry[$key]) {
            unset($this->cache[$key], $this->expiry[$key]);
        }
    }
}
