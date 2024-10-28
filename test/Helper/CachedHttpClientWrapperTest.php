<?php

namespace Helper;

use Dvsa\GovUkAccount\Helper\CachedHttpClientWrapper;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Psr7\Response;
use Mockery as m;
use PHPUnit\Framework\TestCase;
use Psr\Cache\CacheItemPoolInterface;

class CachedHttpClientWrapperTest extends TestCase
{
    protected ClientInterface $httpClient;

    public function setUp(): void
    {
        parent::setUp();
        $this->httpClient = m::mock(ClientInterface::class, \Psr\Http\Client\ClientInterface::class);
    }

    public function testSendRequestWithCacheHit()
    {
        $cache = m::mock(CacheItemPoolInterface::class);
        $cacheItem = m::mock(\Psr\Cache\CacheItemInterface::class);
        $cacheKey = CachedHttpClientWrapper::CACHE_KEY_PREFIX . sha1('http://example.com');
        $cacheValue = ['key' => 'value'];

        $cache->shouldReceive('getItem')
            ->with($cacheKey)
            ->andReturn($cacheItem);

        $cacheItem->shouldReceive('isHit')
            ->andReturn(true);

        $cacheItem->shouldReceive('get')
            ->andReturn(serialize($cacheValue));

        $wrapper = new CachedHttpClientWrapper($this->httpClient, $cache);
        $result = $wrapper->sendGetRequest('http://example.com');

        $this->assertSame($cacheValue, $result);
    }

    public function testSendRequestWithCacheMiss()
    {
        $cache = m::mock(CacheItemPoolInterface::class);
        $cacheItem = m::mock(\Psr\Cache\CacheItemInterface::class);
        $cacheKey = CachedHttpClientWrapper::CACHE_KEY_PREFIX . sha1('http://example.com');
        $cacheValue = ['key' => 'value'];
        $response = new Response(200, [], json_encode($cacheValue));

        $cache->shouldReceive('getItem')
            ->with($cacheKey)
            ->andReturn($cacheItem);

        $cacheItem->shouldReceive('isHit')
            ->andReturn(false);

        $this->httpClient->shouldReceive('request')
            ->with('GET', 'http://example.com', [])
            ->andReturn($response);

        $cacheItem->shouldReceive('expiresAfter')
            ->with(CachedHttpClientWrapper::DEFAULT_CACHE_TTL_SECONDS);

        $cacheItem->shouldReceive('set')
            ->with(serialize($cacheValue));

        $cache->shouldReceive('save')
            ->with($cacheItem);

        $wrapper = new CachedHttpClientWrapper($this->httpClient, $cache);
        $result = $wrapper->sendGetRequest('http://example.com');

        $this->assertSame($cacheValue, $result);
    }

    public function testSendRequestWithCacheMissAndCustomTtl()
    {
        $cache = m::mock(CacheItemPoolInterface::class);
        $cacheItem = m::mock(\Psr\Cache\CacheItemInterface::class);
        $cacheKey = CachedHttpClientWrapper::CACHE_KEY_PREFIX . sha1('http://example.com');
        $cacheValue = ['key' => 'value'];
        $response = new Response(200, [], json_encode($cacheValue));

        $cache->shouldReceive('getItem')
            ->with($cacheKey)
            ->andReturn($cacheItem);

        $cacheItem->shouldReceive('isHit')
            ->andReturn(false);

        $this->httpClient->shouldReceive('request')
            ->with('GET', 'http://example.com', [])
            ->andReturn($response);

        $cacheItem->shouldReceive('expiresAfter')
            ->with(1800);

        $cacheItem->shouldReceive('set')
            ->with(serialize($cacheValue));

        $cache->shouldReceive('save')
            ->with($cacheItem);

        $wrapper = new CachedHttpClientWrapper($this->httpClient, $cache);
        $result = $wrapper->sendGetRequest('http://example.com', [], 1800);

        $this->assertSame($cacheValue, $result);
    }

    public function testSendRequestWithNoCacheSet(): void
    {
        $wrapper = new CachedHttpClientWrapper($this->httpClient, null);
        $cacheValue = ['key' => 'value'];
        $response = new Response(200, [], json_encode($cacheValue));

        $this->httpClient->shouldReceive('request')
            ->with('GET', 'http://example.com', [])
            ->andReturn($response);

        $result = $wrapper->sendGetRequest('http://example.com');

        $this->assertSame($cacheValue, $result);
    }
}
