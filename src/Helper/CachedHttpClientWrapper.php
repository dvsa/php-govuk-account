<?php

namespace Dvsa\GovUkAccount\Helper;

use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\GuzzleException;
use JsonException;
use Psr\Cache\CacheItemPoolInterface;
use Psr\Cache\InvalidArgumentException;
use Psr\Http\Message\ResponseInterface;
use Throwable;

class CachedHttpClientWrapper
{
    public const DEFAULT_CACHE_TTL_SECONDS = 3600;
    public const CACHE_KEY_PREFIX = 'govuk-one-login-oauth2-provider-http-response-';

    private ClientInterface $httpClient;
    private ?CacheItemPoolInterface $cache;

    public function __construct(ClientInterface $httpClient, ?CacheItemPoolInterface $cache)
    {
        $this->httpClient = $httpClient;
        $this->cache = $cache;
    }

    /**
     * @param array<string, mixed> $options
     * @return array<mixed>
     *
     * @throws GuzzleException
     * @throws InvalidArgumentException
     * @throws JsonException
     */
    public function sendGetRequest(string $url, array $options = [], int $cacheTtlSeconds = self::DEFAULT_CACHE_TTL_SECONDS): array
    {
        $cacheKey = self::CACHE_KEY_PREFIX . sha1($url);
        $cacheItem = $this->cache?->getItem($cacheKey);

        if ($cacheItem !== null && $cacheItem->isHit()) {
            // Cached entries are stored as JSON to avoid the PHP object-injection
            // risk that comes with unserialize() on data which may live in a
            // shared backend (e.g. Redis, Memcached).
            $cached = $cacheItem->get();
            if (is_string($cached)) {
                $decoded = json_decode($cached, true, 512, JSON_THROW_ON_ERROR);
                if (is_array($decoded)) {
                    return $decoded;
                }
            }
        }

        $response = $this->httpClient->request('GET', $url, $options);

        $parsedResponse = json_decode($response->getBody()->getContents(), true, 512, JSON_THROW_ON_ERROR);
        if (!is_array($parsedResponse)) {
            throw new JsonException('Expected JSON object/array response from ' . $url);
        }

        if ($this->cache instanceof CacheItemPoolInterface && $cacheItem !== null) {
            $cacheItem->expiresAfter($cacheTtlSeconds);
            $cacheItem->set(json_encode($parsedResponse, JSON_THROW_ON_ERROR));
            $this->cache->save($cacheItem);
        }

        return $parsedResponse;
    }
}
