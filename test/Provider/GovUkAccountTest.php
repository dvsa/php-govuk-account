<?php

namespace Provider;

use Dvsa\GovUkAccount\Exception\InvalidTokenException;
use Dvsa\GovUkAccount\Provider\GovUkAccount;
use Dvsa\GovUkAccount\Token\AccessToken;
use Dvsa\GovUkAccount\Token\GovUkAccountUser;
use Firebase\JWT\CachedKeySet;
use Firebase\JWT\JWT;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Psr7\Response;
use Mockery as m;
use PHPUnit\Framework\TestCase;
use Psr\Cache\CacheItemPoolInterface;

class GovUkAccountTest extends TestCase
{
    // Generated ES256 (P256) (SHA256) keys for unit tests
    const CLIENT_PUBLIC_KEY = 'LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFSU1MWXlXcjZnRDRjTzRhRU40emRKZWo2eXp0UwpQWHdLUTRjcWM0YmcvZ2hZY1FFeS9PcnFoV3VNNzJvL3NaaFB6ZXo1Tjk5cjhxVzlrRWdKTk4wMlJnPT0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0t';
    const CLIENT_PRIVATE_KEY = 'LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1FRUNBUUF3RXdZSEtvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRUp6QWxBZ0VCQkNCeXBGZk54Mk1jTWNiamtPcEgKT2IxdVlsNDRaOVJmWmE5MjYxUXc5dEZia1E9PQotLS0tLUVORCBQUklWQVRFIEtFWS0tLS0t';
    const SERVICE_PUBLIC_KEY = 'LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFZGNxQkwrTUh2TWNldi8wWHI3ZFhvOXdQVFpqLwpuZnA1WGg0dnB4MXJneHdHVHpFbmxuQXFVOVkzdXN4Rml6a2g0VkdkVWc1S3JNSmpnd2NrWWVmdG9BPT0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==';
    const SERVICE_PRIVATE_KEY = 'LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1FRUNBUUF3RXdZSEtvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRUp6QWxBZ0VCQkNETExrUlQ3UGVpaklERm02SEMKZGlYYXJmbjY0emxTNDhreXdJMWE1em1NMHc9PQotLS0tLUVORCBQUklWQVRFIEtFWS0tLS0t';
    const SERVICE_CORE_IDENTITY_CLAIM_PUBLIC_KEY = 'LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFSm1sbW92MmtYTHB4NVd2YzMxVHRIZGZjRktNYwp6dGliZHNraHFCL1lSSDEzV2dOOXBpTkVKRUJGS3JjZGQ5SEE4d1VEWDdsMjN5bFB4REVqZnRROXh3PT0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0t';
    const SERVICE_CORE_IDENTITY_CLAIM_PRIVATE_KEY = 'LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1FRUNBUUF3RXdZSEtvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRUp6QWxBZ0VCQkNDSkh1bHVwZ3Bqclo5MitaalUKZ1E5RmY4YVhxNkZIek1EeVJuejNHY1pjNGc9PQotLS0tLUVORCBQUklWQVRFIEtFWS0tLS0t';
    const SERVICE_PUBLIC_KEY_JWK = [
        'keys' => [
                0 => [  // JWK (Public) for SERVICE_PUBLIC/PRIVATE_KEY
                    'kty' => 'EC',
                    'use' => 'sig',
                    'crv' => 'P-256',
                    'kid' => 'N-NegtAr3bnZC4d2Pcav2sH5UNOp5tpbXg8phQl4Tyg',
                    'x' => 'dcqBL-MHvMcev_0Xr7dXo9wPTZj_nfp5Xh4vpx1rgxw',
                    'y' => 'Bk8xJ5ZwKlPWN7rMRYs5IeFRnVIOSqzCY4MHJGHn7aA',
                    'alg' => 'ES256',
                ],
                1 => [  // JWK (Public) for SERVICE_CORE_IDENTITY_PUBLIC/PRIVATE_KEY
                    'kty' =>'EC',
                    'use' =>'sig',
                    'crv' =>'P-256',
                    'kid' =>'swfvlyjqVu0Budk52Fl95nN7jPWGJ1CHPdY-Q5itATc',
                    'x' =>'Jmlmov2kXLpx5Wvc31TtHdfcFKMcztibdskhqB_YRH0',
                    'y' =>'d1oDfaYjRCRARSq3HXfRwPMFA1-5dt8pT8QxI37UPcc',
                    'alg' =>'ES256',
                ]
            ],
        ];

    protected ClientInterface $httpClient;

    public function setUp(): void
    {
        parent::setUp();
        $this->httpClient = m::mock(ClientInterface::class, \Psr\Http\Client\ClientInterface::class);
    }

    protected function getProvider(array $options = [], array $collaborators = [], CacheItemPoolInterface $cache = null): GovUkAccount
    {
        $options = array_merge([
            'client_id' => 'mock_client_id',
            'redirect_uri' => [
                'logged_in' => 'https://service.example/logged-in',
            ],
            'keys' => [
                'algorithm' => 'RS256',
                'private_key' => static::CLIENT_PRIVATE_KEY,
            ],
            'core_identity_did_document_url' => 'https://iodc.example/.well-known/did.json',
            'expected_core_identity_issuer' => 'oidc.example',
            'discovery_endpoint' => 'https://iodc.example/.well-known/openid-configuration',
        ], $options);

        $provider = new GovUkAccount($options, $collaborators, $cache);

        $this->httpClient
            ->expects('request')
            ->once()
            ->withArgs(['GET', 'https://iodc.example/.well-known/openid-configuration', []])
            ->andReturn(new Response(200, [], json_encode($this->getOpenIdConfiguration())))
            ->byDefault();

        $this->httpClient
            ->expects('request')
            ->once()
            ->withArgs(['GET', 'https://oidc.example/.well-known/jwks.json', []])
            ->andReturn(new Response(200, [], json_encode(static::SERVICE_PUBLIC_KEY_JWK)))
            ->byDefault();

        $this->httpClient
            ->expects('request')
            ->once()
            ->withArgs(['GET', 'https://iodc.example/.well-known/did.json', []])
            ->andReturn(new Response(200, [], json_encode([
                    'assertionMethod' => [
                        [
                            'id' => 'swfvlyjqVu0Budk52Fl95nN7jPWGJ1CHPdY-Q5itATc',
                            'type' => 'JsonWebKey',
                            'publicKeyJwk' => static::SERVICE_PUBLIC_KEY_JWK['keys'][1],
                        ],
                    ],
                ]))
            )
            ->byDefault();

        $provider->setHttpClient($this->httpClient);

        return $provider;
    }

    protected function getOpenIdConfiguration(array $result = []): array
    {
        return array_merge([
            'authorization_endpoint' => 'https://oidc.example/authorize',
            'token_endpoint' => 'https://oidc.example/token',
            'userinfo_endpoint' => 'https://oidc.example/userinfo',
            'jwks_uri' => 'https://oidc.example/.well-known/jwks.json',
            'issuer' => 'oidc.example',
        ], $result);
    }

    /**
     * @doesNotPerformAssertions
     */
    public function testStringIdentityAssurancePublicKey(): void
    {
        $options = [
            'keys' => [
                'algorithm' => 'RS256',
                'private_key' => static::CLIENT_PRIVATE_KEY,
                'identity_assurance_public_key' => json_encode(static::SERVICE_PUBLIC_KEY_JWK['keys'][1]),
            ]
        ];

        // The logic that is being tested happens in the `__construct` method - `parseIdentityAssuranceKey`.
        $this->getProvider($options);
    }

    /**
     * @dataProvider dataProviderSetGetNonce
     */
    public function testSetGetNonce(?string $value): void
    {
        $provider = $this->getProvider();
        $nonce = $provider->setNonce($value);

        if ($value === null) {
            $this->assertNotNull($nonce);
            $this->assertNotNull($provider->getNonce());
        } else {
            $this->assertEquals($value, $nonce);
            $this->assertEquals($value, $provider->getNonce());
        }
        $this->assertEquals($nonce, $provider->getNonce());
    }

    public function dataProviderSetGetNonce(): array
    {
        return [
            'Sets the value specified' => [
                'SpecificNonceValue'
            ],
            'Sets a random value if not specified' => [
                null
            ],
        ];
    }

    /**
     * @dataProvider dataProviderSetGetState
     */
    public function testSetState(?string $value): void
    {
        $provider = $this->getProvider();
        $state = $provider->setState($value);

        if ($value === null) {
            $this->assertNotNull($state);
            $this->assertNotNull($provider->getState());
        } else {
            $this->assertEquals($value, $state);
            $this->assertEquals($value, $provider->getState());
        }
        $this->assertEquals($state, $provider->getState());
    }

    public function dataProviderSetGetState(): array
    {
        return [
            'Sets the value specified' => [
                'SpecificStateValue'
            ],
            'Sets a random value if not specified' => [
                null
            ],
        ];
    }

    public function testAuthorizationUrl(): void
    {
        $provider = $this->getProvider();
        $url = $provider->getAuthorizationUrl();
        $uri = parse_url($url);
        parse_str($uri['query'], $query);

        $this->assertArrayHasKey('client_id', $query);
        $this->assertArrayHasKey('redirect_uri', $query);
        $this->assertArrayHasKey('state', $query);
        $this->assertArrayHasKey('nonce', $query);
        $this->assertArrayHasKey('response_type', $query);
        $this->assertNotNull($provider->getState());
        $this->assertNotNull($provider->getNonce());
    }

    public function testGetAccessToken(): void
    {
        $provider = $this->getProvider();

        $createdAccessToken = $this->createAccessToken();
        $createdIdToken = $this->createIdToken($provider->setNonce());
        $createdRefreshToken = $this->createRefreshToken();

        $this->httpClient
            ->expects('send')
            ->once()
            ->andReturn(new Response(200, [], json_encode([
                'access_token' => $createdAccessToken,
                'token_type' => 'Bearer',
                'expires_in' => 3600,
                'refresh_token' => $createdRefreshToken,
                'id_token' => $createdIdToken,
            ])));

        $token = $provider->getAccessToken('authorization_code', [
            'scope' => $provider::DEFAULT_SCOPES,
            'code' => 'test-code',
        ]);

        $this->assertInstanceOf(\Dvsa\GovUkAccount\Token\AccessToken::class, $token);
    }

    /**
     * @dataProvider dataProviderValidateAccessToken
     */
    public function testValidateAccessToken(array $accessTokenPayload, bool $expectException): void
    {
        if ($expectException) {
            $this->expectException(InvalidTokenException::class);
        } else {
            $this->expectNotToPerformAssertions();
        }

        $provider = $this->getProvider();

        $createdAccessToken = $this->createAccessToken($accessTokenPayload);
        $createdIdToken = $this->createIdToken($provider->setNonce());
        $createdRefreshToken = $this->createRefreshToken();

        $this->httpClient
            ->expects('send')
            ->once()
            ->andReturn(new Response(200, [], json_encode([
                'access_token' => $createdAccessToken,
                'token_type' => 'Bearer',
                'expires_in' => 3600,
                'refresh_token' => $createdRefreshToken,
                'id_token' => $createdIdToken,
            ])));

        $token = $provider->getAccessToken('authorization_code', [
            'scope' => $provider::DEFAULT_SCOPES,
            'code' => 'test-code',
        ]);

        $provider->validateAccessToken($token->getToken());
    }

    public function dataProviderValidateAccessToken(): array
    {
        return [
            'Valid Token' => [[
                // Default claims are valid
            ], false],
            'Token iss does not match openid-configuration' => [[
                'iss' => 'unknown-issuer'
            ], true],
            'Token client_id does not match configured client_id' => [[
                'client_id' => 'unknown-client-id'
            ], true],
        ];
    }

    /**
     * @dataProvider dataProviderValidateIdToken
     */
    public function testValidateIdToken(array $idTokenPayload, bool $expectException): void
    {
        if ($expectException) {
            $this->expectException(InvalidTokenException::class);
        } else {
            $this->expectNotToPerformAssertions();
        }

        $provider = $this->getProvider();

        $nonce = $idTokenPayload['nonce'] ?? 'valid-nonce';
        $createdAccessToken = $this->createAccessToken();
        $createdIdToken = $this->createIdToken($provider->setNonce($nonce), $idTokenPayload);
        $createdRefreshToken = $this->createRefreshToken();

        $this->httpClient
            ->expects('send')
            ->once()
            ->andReturn(new Response(200, [], json_encode([
                'access_token' => $createdAccessToken,
                'token_type' => 'Bearer',
                'expires_in' => 3600,
                'refresh_token' => $createdRefreshToken,
                'id_token' => $createdIdToken,
            ])));

        $token = $provider->getAccessToken('authorization_code', [
            'scope' => $provider::DEFAULT_SCOPES,
            'code' => 'test-code',
        ]);

        $provider->validateIdToken($token->getIdToken(), 'valid-nonce');
    }

    public function dataProviderValidateIdToken(): array
    {
        return [
            'Valid Token' => [[
                // Default claims are valid
            ], false],
            'Token iss does not match openid-configuration' => [[
                'iss' => 'unknown-issuer'
            ], true],
            'Token aud does not match configured client_id' => [[
                'aud' => 'unknown-client-id'
            ], true],
            'Token nonce does not match initial nonce' => [[
                'nonce' => 'invalid-nonce'
            ], true],
        ];
    }

    public function testGetResourceOwner(): void
    {
        $provider = $this->getProvider();

        $this->httpClient
            ->expects('send')
            ->once()
            ->andReturn(new Response(200, [], json_encode([
                'sub' => 'test-subject',
            ])));

        $token = new AccessToken([
            'access_token' => $this->createAccessToken(),
            'id_token' => $this->createIdToken($provider->setNonce())
            ], $provider);

        $userInfo = $provider->getResourceOwner($token);
        $this->assertInstanceOf(GovUkAccountUser::class, $userInfo);
        $this->assertEquals('test-subject', $userInfo->getField('sub'));
        $this->assertEquals('test-subject', $userInfo->getId(), "getID does not return subject");
    }

    public function testGetResourceOwnerStdClassReturnedAsArray(): void
    {
        $provider = $this->getProvider();

        $obj = new \stdClass();
        $obj->testProp = 'testValue';

        $this->httpClient
            ->expects('send')
            ->once()
            ->andReturn(new Response(200, [], json_encode([
                'sub' => 'test-subject',
                'test' => $obj
            ])));

        $token = new AccessToken([
            'access_token' => $this->createAccessToken(),
            'id_token' => $this->createIdToken($provider->setNonce())
        ], $provider);

        $userInfo = $provider->getResourceOwner($token);
        $this->assertInstanceOf(GovUkAccountUser::class, $userInfo);
        $this->assertIsArray($userInfo->getField('test'));
        $this->assertArrayHasKey('testProp', $userInfo->getField('test'));
        $this->assertEquals('testValue', $userInfo->getField('test')['testProp']);
        $this->assertEquals('test-subject', $userInfo->getField('sub'));
        $this->assertEquals('test-subject', $userInfo->getId(), "getID does not return subject");
    }

    /**
     * @dataProvider dataProviderValidateCoreIdentityToken
     */
    public function testValidateCoreIdentityClaim(array $coreIdentityTokenPayload, bool $expectException): void
    {
        if ($expectException) {
            $this->expectException(InvalidTokenException::class);
        } else {
            $this->expectNotToPerformAssertions();
        }

        $provider = $this->getProvider();

        // Mock send, with request object with property path as /userinfo

        $this->httpClient
            ->expects('send')
            ->with(m::on(function ($request) {
                return $request->getUri()->getPath() === '/userinfo';
            }))
            ->once()
            ->andReturn(new Response(200, [], json_encode([
                'sub' => 'test-subject',
                GovUkAccountUser::KEY_CLAIMS_CORE_IDENTITY => $this->createCoreIdentityToken($coreIdentityTokenPayload),
            ])));

        $token = new AccessToken([
            'access_token' => $this->createAccessToken(),
            'id_token' => $this->createIdToken($provider->setNonce())
        ], $provider);

        $provider->getResourceOwner($token);
    }

    public function dataProviderValidateCoreIdentityToken(): array
    {
        return [
            'Valid Token' => [[
                // Default claims are valid
            ], false],
            'Token iss does not match openid-configuration' => [[
                'iss' => 'unknown-issuer'
            ], true],
            'Token sub does not match id_token sub' => [[
                'sub' => 'unknown-subject'
            ], true],
        ];
    }

    public function testLoadJwksRespectsCacheItemPoolInterfaceAndReturnsCachedKeySet(): void
    {
        $cacheObject = m::mock(CacheItemPoolInterface::class)->makePartial();

        $provider = $this->getProvider([], [], $cacheObject);

        $this->assertInstanceOf(CachedKeySet::class, $provider->loadJwks('test'));
    }

    protected function createAccessToken(array $payload = []): string
    {
        return JWT::encode(array_merge([
            'sub' => 'test-sub',
            'iss' => 'oidc.example',
            'client_id' => 'mock_client_id',
            'exp' => (new \DateTimeImmutable())->getTimestamp() + 3600,
            'iat' => (new \DateTimeImmutable())->getTimestamp() - 10,
        ], $payload), base64_decode(static::SERVICE_PRIVATE_KEY), 'ES256', 'N-NegtAr3bnZC4d2Pcav2sH5UNOp5tpbXg8phQl4Tyg');
    }

    protected function createIdToken(string $nonce, array $payload = []): string
    {
        return JWT::encode(array_merge([
            'sub' => 'test-sub',
            'iss' => 'oidc.example',
            'nonce' => $nonce,
            'aud' => 'mock_client_id',
            'exp' => (new \DateTimeImmutable())->getTimestamp() + 3600,
            'iat' => (new \DateTimeImmutable())->getTimestamp() - 10,
        ], $payload), base64_decode(static::SERVICE_PRIVATE_KEY), 'ES256', 'N-NegtAr3bnZC4d2Pcav2sH5UNOp5tpbXg8phQl4Tyg');
    }

    protected function createRefreshToken(array $payload = []): string
    {
        return JWT::encode(array_merge([
            'sub' => 'test-sub',
            'iss' => 'oidc.example',
            'scope' => [
                'openid',
                'offline_access',
            ],
            'exp' => (new \DateTimeImmutable())->getTimestamp() + 9000,
            'iat' => (new \DateTimeImmutable())->getTimestamp() - 10,
        ], $payload), base64_decode(static::SERVICE_PRIVATE_KEY), 'ES256', 'N-NegtAr3bnZC4d2Pcav2sH5UNOp5tpbXg8phQl4Tyg');
    }

    protected function createCoreIdentityToken(array $payload = []): string
    {
        return JWT::encode(array_merge([
            'sub' => 'test-sub',
            'aud' => 'mock_client_id',
            'iss' => 'oidc.example',
            'exp' => (new \DateTimeImmutable())->getTimestamp() + 9000,
            'iat' => (new \DateTimeImmutable())->getTimestamp() - 10,
        ], $payload), base64_decode(static::SERVICE_CORE_IDENTITY_CLAIM_PRIVATE_KEY), 'ES256', 'swfvlyjqVu0Budk52Fl95nN7jPWGJ1CHPdY-Q5itATc');
    }
}
