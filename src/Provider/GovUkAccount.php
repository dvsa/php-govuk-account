<?php

namespace Dvsa\GovUkAccount\Provider;

use ArrayAccess;
use DateTimeImmutable;
use Dvsa\GovUkAccount\Exception\ApiException;
use Dvsa\GovUkAccount\Exception\InvalidTokenException;
use Dvsa\GovUkAccount\Helper\Assert;
use Dvsa\GovUkAccount\Helper\CachedHttpClientWrapper;
use Dvsa\GovUkAccount\Helper\DidDocumentParser;
use Dvsa\GovUkAccount\Token\GovUkAccountUser;
use Exception;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use GuzzleHttp\ClientInterface as HttpClientInterface;
use GuzzleHttp\Exception\GuzzleException;
use Illuminate\Support\Collection;
use InvalidArgumentException;
use League\OAuth2\Client\Grant\AbstractGrant;
use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Tool\BearerAuthorizationTrait;
use Psr\Cache\CacheItemPoolInterface;
use Psr\Http\Message\ResponseInterface;

class GovUkAccount extends AbstractProvider
{
    use BearerAuthorizationTrait;

    public const DEFAULT_SCOPES = ['openid', 'offline_access'];
    public const SCOPE_SEPARATOR = ' ';
    public const DEFAULT_ACCESS_TOKEN_EXPIRY = '+5 Minute';

    protected string $nonce;
    protected string $algorithm;
    protected string $privateKey;
    protected string $loggedInUrl;
    protected string $expectedCoreIdentityIssuer;

    protected string $openIdConnectConfigurationUrl;

    /** @var array<string, mixed>|null */
    protected ?array $openIdConnectConfiguration = null;

    /** @var ArrayAccess<string, Key>|null */
    protected ?ArrayAccess $govUkSignInPublicKeys = null;
    protected string $core_identity_did_document_url;

    /** @var array<string, Key> */
    protected array $coreIdentityPublicKeys;

    protected CachedHttpClientWrapper $cachedHttpClientWrapper;

    /**
     * @param array<string, mixed> $options
     * @param array<string, mixed> $collaborators
     *
     * @throws ApiException
     * @throws \Psr\Cache\InvalidArgumentException
     * @throws \InvalidArgumentException When a required option is missing or has the wrong type.
     */
    public function __construct(
        array $options = [],
        array $collaborators = [],
        protected ?CacheItemPoolInterface $cache = null
    ) {
        parent::__construct($options, $collaborators);

        $context = self::class . ' configuration';

        $this->clientId = Assert::requireString($options, $context, 'client_id');
        $this->algorithm = Assert::requireString($options, $context, 'keys', 'algorithm');

        $privateKeyB64 = Assert::requireString($options, $context, 'keys', 'private_key');
        $decodedKey = base64_decode($privateKeyB64, true);
        if ($decodedKey === false) {
            throw new InvalidArgumentException($context . ': option "keys.private_key" is not valid base64');
        }
        $this->privateKey = $decodedKey;

        $loggedInUrl = Assert::requireString($options, $context, 'redirect_uri', 'logged_in');
        $this->loggedInUrl = $loggedInUrl;
        $this->redirectUri = $loggedInUrl;

        $this->expectedCoreIdentityIssuer = Assert::requireString($options, $context, 'expected_core_identity_issuer');
        $this->openIdConnectConfigurationUrl = Assert::requireString($options, $context, 'discovery_endpoint');
        $this->core_identity_did_document_url = Assert::requireString($options, $context, 'core_identity_did_document_url');
    }

    public function setHttpClient(HttpClientInterface $client): GovUkAccount|static
    {
        parent::setHttpClient($client);

        $this->cachedHttpClientWrapper = new CachedHttpClientWrapper(
            $this->getHttpClient(),
            $this->cache
        );

        return $this;
    }

    /**
     * @return array<string, Key>
     *
     * @throws GuzzleException
     * @throws \Psr\Cache\InvalidArgumentException
     * @throws \JsonException
     */
    private function parseDidDocument(string $url): array
    {
        /** @var array<string, mixed> $didDocument */
        $didDocument = $this->cachedHttpClientWrapper->sendGetRequest(url: $url, cacheTtlSeconds: 3600);

        return DidDocumentParser::parseToKeyArray($didDocument);
    }

    /**
     * Sets the state used for GOV.UK Account integration; state is replayed when redirected back to service.
     *
     * Note: Not specifying or empty($state) results in setting a randomly generated one.
     *
     * @param string|null $state
     *
     * @return string
     */
    public function setState(?string $state = null): string
    {
        if ($state === null || $state === '') {
            $state = $this->getRandomState();
        }
        $this->state = $state;

        return $this->state;
    }

    public function getBaseAuthorizationUrl(): string
    {
        return $this->getOpenIdConnectConfiguration('authorization_endpoint');
    }

    /**
     * @throws ApiException
     */
    protected function getOpenIdConnectConfiguration(string $key): string
    {
        if (!isset($this->openIdConnectConfiguration)) {
            $this->openIdConnectConfiguration = $this->loadOpenIdConnectConfiguration();
        }

        if (!array_key_exists($key, $this->openIdConnectConfiguration)) {
            throw new InvalidArgumentException(
                "Cannot find {$key} in openIdConnectConfiguration"
            );
        }

        $value = $this->openIdConnectConfiguration[$key];
        if (!is_string($value)) {
            throw new InvalidArgumentException(sprintf(
                'OpenID Connect configuration key "%s" is not a string (got %s)',
                $key,
                get_debug_type($value),
            ));
        }

        return $value;
    }

    /**
     * @return array<string, mixed>
     */
    private function loadOpenIdConnectConfiguration(): array
    {
        try {
            $config = $this->cachedHttpClientWrapper->sendGetRequest(url: $this->openIdConnectConfigurationUrl, cacheTtlSeconds: 3600);
        } catch (GuzzleException $e) {
            throw new ApiException(
                'Error loading OpenID Connect Configuration',
                $e->getCode(),
                $e
            );
        }

        $typed = [];
        foreach ($config as $key => $value) {
            if (!is_string($key)) {
                throw new ApiException('OpenID Connect configuration contains non-string key: ' . get_debug_type($key));
            }
            $typed[$key] = $value;
        }

        return $typed;
    }

    /**
     * @param array<array-key, mixed> $params
     */
    public function getBaseAccessTokenUrl(array $params): string
    {
        return $this->getOpenIdConnectConfiguration('token_endpoint');
    }

    public function getResourceOwnerDetailsUrl(AccessToken $token): string
    {
        return $this->getOpenIdConnectConfiguration('userinfo_endpoint');
    }

    public function getLoggedInUrl(): string
    {
        return $this->loggedInUrl;
    }

    /**
     * @return array<string, mixed>
     *
     * @throws InvalidTokenException
     * @throws ApiException
     */
    public function validateAccessToken(string $token): array
    {
        $keySet = $this->getGovUkSignInPublicKeys();

        /** @var array<string, mixed> $tokenClaims */
        $tokenClaims = (array)JWT::decode($token, $keySet);

        $issuer = $tokenClaims['iss'] ?? null;
        $expectedIssuer = $this->getOpenIdConnectConfiguration('issuer');
        if ($issuer !== $expectedIssuer) {
            throw new InvalidTokenException(sprintf(
                'The Issuer of the access token is invalid: %s !== %s',
                Assert::describe($issuer),
                $expectedIssuer,
            ));
        }

        $clientId = $tokenClaims['client_id'] ?? null;
        if ($clientId !== $this->clientId) {
            throw new InvalidTokenException(sprintf(
                'The client_id of the access token is invalid: %s !== %s',
                Assert::describe($clientId),
                $this->clientId,
            ));
        }

        // IAT, EXP, NBF are checked by JWT::decode();
        return $tokenClaims;
    }

    /**
     * @return ArrayAccess<string, Key>
     *
     * @throws ApiException
     * @throws GuzzleException
     */
    protected function getGovUkSignInPublicKeys(): ArrayAccess
    {
        if ($this->govUkSignInPublicKeys === null) {
            $this->govUkSignInPublicKeys = $this->loadJwks($this->getOpenIdConnectConfiguration('jwks_uri'));
        }

        return $this->govUkSignInPublicKeys;
    }

    /**
     * @return ArrayAccess<string, Key>
     *
     * @throws ApiException
     * @throws GuzzleException
     */
    public function loadJwks(string $jwksUrl): ArrayAccess
    {
        try {
            $response = $this->cachedHttpClientWrapper->sendGetRequest(url: $jwksUrl, cacheTtlSeconds: 3600);
        } catch (GuzzleException $e) {
            throw new ApiException(
                'Error loading JWKs',
                $e->getCode(),
                $e
            );
        }

        /** @var Collection<string, Key> $collection */
        $collection = new Collection(JWK::parseKeySet($response));

        return $collection;
    }

    /**
     * @return array<string, mixed>
     *
     * @throws InvalidTokenException
     * @throws ApiException
     */
    public function validateIdToken(string $token, ?string $nonce = null): array
    {
        $keySet = $this->getGovUkSignInPublicKeys();

        /** @var array<string, mixed> $tokenClaims */
        $tokenClaims = (array)JWT::decode($token, $keySet);

        $issuer = $tokenClaims['iss'] ?? null;
        $expectedIssuer = $this->getOpenIdConnectConfiguration('issuer');
        if ($issuer !== $expectedIssuer) {
            throw new InvalidTokenException(sprintf(
                'The Issuer of the ID token is invalid: %s !== %s',
                Assert::describe($issuer),
                $expectedIssuer,
            ));
        }

        $audience = $tokenClaims['aud'] ?? null;
        if ($audience !== $this->clientId) {
            throw new InvalidTokenException(sprintf(
                'The aud of the ID token is invalid: %s !== %s',
                Assert::describe($audience),
                $this->clientId,
            ));
        }

        if ($nonce !== null) {
            $claimNonce = $tokenClaims['nonce'] ?? null;
            if ($claimNonce !== $nonce) {
                throw new InvalidTokenException(sprintf(
                    'The nonce of the ID token is invalid: %s !== %s',
                    Assert::describe($claimNonce),
                    $nonce,
                ));
            }
        }

        // IAT, EXP, NBF are checked by JWT::decode();
        return $tokenClaims;
    }

    /**
     * {@inheritDoc}
     *
     * @param array<string, mixed> $options
     */
    public function getAccessToken(
        $grant,
        array $options = []
    ): \Dvsa\GovUkAccount\Token\AccessToken {
        $issuedAt = new DateTimeImmutable();
        $expiryDelta = $options['access_token_expiry_delta'] ?? static::DEFAULT_ACCESS_TOKEN_EXPIRY;
        if (!is_string($expiryDelta)) {
            throw new InvalidArgumentException(sprintf(
                'Option "access_token_expiry_delta" must be a string, got %s',
                get_debug_type($expiryDelta),
            ));
        }
        $expiresAt = $issuedAt->modify($expiryDelta);

        if (!$expiresAt instanceof DateTimeImmutable) {
            throw new InvalidArgumentException('Could not create expiresAt using a delta on issuedAt.');
        }

        $token = [
            'aud' => $this->getAccessTokenUrl([]),
            'iss' => $this->clientId,
            'sub' => $this->clientId,
            'exp' => $expiresAt->getTimestamp(),
            'jti' => $this->createJwtId(),
            'iat' => $issuedAt->getTimestamp(),
        ];

        $encodedToken = JWT::encode(
            $token,
            $this->privateKey,
            $this->algorithm
        );

        $options += [
            'client_assertion' => $encodedToken,
            'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        ];

        $accessToken = parent::getAccessToken($grant, $options);
        assert($accessToken instanceof \Dvsa\GovUkAccount\Token\AccessToken);

        return $accessToken;
    }

    /**
     * Generates a UUIDv4 string. Using a cryptographically secure pseudo-random byte generator.
     * Conforms to RFC 4122.
     *
     * @return string
     * @throws Exception
     */
    private function createJwtId(): string
    {
        $bytes = random_bytes(16);

        $bytes[6] = chr(ord($bytes[6]) & 0x0f | 0x40);
        $bytes[8] = chr(ord($bytes[8]) & 0x3f | 0x80);

        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($bytes), 4));
    }

    /**
     * @param array<array-key, mixed> $options
     *
     * @return array<array-key, mixed>
     */
    protected function getAuthorizationParameters(array $options): array
    {
        $options = parent::getAuthorizationParameters($options);

        if (!isset($this->nonce) || $this->nonce === '') {
            $this->setNonce();
        }
        $options['nonce'] = $this->getNonce();

        return $options;
    }

    public function getNonce(): string
    {
        return $this->nonce;
    }

    /**
     * Sets the nonce used for GOV.UK Account integration.
     *
     * Note: Not specifying or empty($nonce) results in setting a randomly generated one.
     *
     * @param string|null $nonce
     *
     * @return string
     */
    public function setNonce(?string $nonce = null): string
    {
        if ($nonce === null || $nonce === '') {
            $nonce = $this->getRandomState();
        }
        $this->nonce = $nonce;

        return $this->nonce;
    }

    /**
     * @return list<string>
     */
    protected function getDefaultScopes(): array
    {
        return self::DEFAULT_SCOPES;
    }

    protected function getScopeSeparator(): string
    {
        return self::SCOPE_SEPARATOR;
    }

    /**
     * @param mixed $data
     *
     * @throws ApiException
     */
    protected function checkResponse(ResponseInterface $response, $data): void
    {
        if ($response->getStatusCode() !== 200) {
            throw new ApiException(
                'Request returned non-200 status code',
                $response->getStatusCode(),
                null,
                [$response, $data]
            );
        }
    }

    /**
     * @param array<array-key, mixed> $response
     */
    protected function createAccessToken(
        array $response,
        AbstractGrant $grant
    ): \Dvsa\GovUkAccount\Token\AccessToken {
        /** @var array<string, mixed> $response */
        return new \Dvsa\GovUkAccount\Token\AccessToken($response, $this);
    }

    /**
     * @param array<array-key, mixed> $response
     *
     * @throws InvalidTokenException
     * @throws \JsonException
     */
    protected function createResourceOwner(
        array $response,
        AccessToken $token
    ): GovUkAccountUser {
        assert($token instanceof \Dvsa\GovUkAccount\Token\AccessToken);

        // Validate CoreIdentity JWT if present.
        $coreIdentityToken = $response[GovUkAccountUser::KEY_CLAIMS_CORE_IDENTITY] ?? null;
        if (is_string($coreIdentityToken) && $coreIdentityToken !== '') {
            $response[GovUkAccountUser::KEY_CLAIMS_CORE_IDENTITY_DECODED] = $this->validateCoreIdentityClaim(
                $coreIdentityToken,
                $token->getIdTokenClaims()
            );
        }

        $encoded = json_encode($response, JSON_THROW_ON_ERROR);

        $decoded = json_decode($encoded, true, 512, JSON_THROW_ON_ERROR);
        if (!is_array($decoded)) {
            throw new \JsonException('Resource owner payload did not decode to an array');
        }

        /** @var array<string, mixed> $decoded */
        return new GovUkAccountUser($decoded);
    }

    /**
     * @param array<string, mixed> $idTokenClaims
     *
     * @return array<string, mixed>
     *
     * @throws InvalidTokenException
     * @throws GuzzleException
     */
    public function validateCoreIdentityClaim(
        string $token,
        array $idTokenClaims
    ): array {
        $keys = $this->parseDidDocument(
            $this->core_identity_did_document_url
        );

        /** @var array<string, mixed> $claims */
        $claims = (array)JWT::decode($token, $keys);

        $issuer = $claims['iss'] ?? null;
        if ($issuer !== $this->expectedCoreIdentityIssuer) {
            throw new InvalidTokenException(sprintf(
                'The issuer (iss) for CoreIdentityJWT is invalid: %s (expecting %s)',
                Assert::describe($issuer),
                $this->expectedCoreIdentityIssuer
            ));
        }

        $audience = $claims['aud'] ?? null;
        if ($audience !== $this->clientId) {
            throw new InvalidTokenException(sprintf(
                'The audience (aud) for CoreIdentityJWT is invalid: %s (expecting %s)',
                Assert::describe($audience),
                $this->clientId
            ));
        }

        $subject = $claims['sub'] ?? null;
        $expectedSubject = $idTokenClaims['sub'] ?? null;
        if ($subject !== $expectedSubject) {
            throw new InvalidTokenException(sprintf(
                'The subject (sub) for CoreIdentityJWT is invalid and does not match the subject for the ID Token: %s (expecting %s)',
                Assert::describe($subject),
                Assert::describe($expectedSubject)
            ));
        }

        return $claims;
    }
}
