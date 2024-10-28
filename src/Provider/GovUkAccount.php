<?php

namespace Dvsa\GovUkAccount\Provider;

use ArrayAccess;
use DateTimeImmutable;
use Dvsa\GovUkAccount\Exception\ApiException;
use Dvsa\GovUkAccount\Exception\InvalidTokenException;
use Dvsa\GovUkAccount\Helper\CachedHttpClientWrapper;
use Dvsa\GovUkAccount\Helper\DidDocumentParser;
use Dvsa\GovUkAccount\Token\GovUkAccountUser;
use Exception;
use Firebase\JWT\CachedKeySet;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use GuzzleHttp\ClientInterface as HttpClientInterface;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Psr7\HttpFactory;
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
    public const DEFAULT_SCOPES = ['openid', 'offline_access'];
    public const SCOPE_SEPARATOR = ' ';
    public const DEFAULT_ACCESS_TOKEN_EXPIRY = '+5 Minute';

    protected string $nonce;
    protected string $algorithm;
    protected string $privateKey;
    protected string $loggedInUrl;
    protected string $expectedCoreIdentityIssuer;

    protected string $openIdConnectConfigurationUrl;
    protected ?array $openIdConnectConfiguration;

    protected ?ArrayAccess $govUkSignInPublicKeys;
    protected string $core_identity_did_document_url;
    protected array $coreIdentityPublicKeys;

    protected CachedHttpClientWrapper $cachedHttpClientWrapper;

    use BearerAuthorizationTrait;

    /**
     * @throws ApiException
     * @throws \Psr\Cache\InvalidArgumentException
     */
    public function __construct(
        array                  $options = [],
        array                  $collaborators = [],
        protected ?CacheItemPoolInterface $cache = null
    ) {
        parent::__construct($options, $collaborators);

        $this->clientId = $options['client_id'];
        $this->algorithm = $options['keys']['algorithm'];
        $this->privateKey = base64_decode((string) $options['keys']['private_key']);
        $this->loggedInUrl = $this->redirectUri = $options['redirect_uri']['logged_in'];
        $this->expectedCoreIdentityIssuer = $options['expected_core_identity_issuer'];
        $this->openIdConnectConfigurationUrl = $options['discovery_endpoint'];
        $this->core_identity_did_document_url = $options['core_identity_did_document_url'];
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
     * @return Key[]
     * @throws GuzzleException
     */
    private function parseDidDocument(string $url): array
    {
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
    public function setState(string $state = null): string
    {
        if (empty($state)) {
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
     * @param string $key
     * @return string
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

        return $this->openIdConnectConfiguration[$key];
    }

    private function loadOpenIdConnectConfiguration(): array
    {
        try {
            return $this->cachedHttpClientWrapper->sendGetRequest(url: $this->openIdConnectConfigurationUrl, cacheTtlSeconds: 3600);
        } catch (GuzzleException $e) {
            throw new ApiException(
                'Error loading OpenID Connect Configuration',
                $e->getCode(),
                $e
            );
        }
    }

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
     * @throws InvalidTokenException
     */
    public function validateAccessToken(string $token): array
    {
        /**
         * The typing of the JWT library is not quite right for `decode()` method for PHPStan as it doesn't accept ArrayAccess.
         * The following type is required to cast `ArrayAccess<string, Key>` to just an expected `array<string, Key>`.
         *
         * Can be removed once fixed in the JWT library.
         *
         * @var array<string, Key> $keySet
         */
        $keySet = $this->getGovUkSignInPublicKeys();

        $tokenClaims = (array)JWT::decode(
            $token,
            $keySet
        );

        if ($tokenClaims['iss']
            !== $this->getOpenIdConnectConfiguration('issuer')
        ) {
            throw new InvalidTokenException(
                'The Issuer of the access token is invalid: '
                . $tokenClaims['iss'] . ' !== '
                . $this->getOpenIdConnectConfiguration('issuer')
            );
        }

        if ($tokenClaims['client_id'] !== $this->clientId) {
            throw new InvalidTokenException(
                'The client_id of the access token is invalid: '
                . $tokenClaims['client_id'] . ' !== ' . $this->clientId
            );
        }

        // IAT, EXP, NBF are checked by JWT::decode();
        return $tokenClaims;
    }

    /**
     * @throws ApiException
     * @throws GuzzleException
     */
    protected function getGovUkSignInPublicKeys(): ArrayAccess
    {
        if (!isset($this->govUkSignInPublicKeys)) {
            $this->govUkSignInPublicKeys = $this->loadJwks($this->getOpenIdConnectConfiguration('jwks_uri'));
        }

        return $this->govUkSignInPublicKeys;
    }

    /**
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
        return new Collection(JWK::parseKeySet($response));
    }

    /**
     * @throws InvalidTokenException
     */
    public function validateIdToken(string $token, string $nonce = null): array
    {
        /**
         * The typing of the JWT library is not quite right for `decode()` method for PHPStan as it doesn't accept ArrayAccess.
         * The following type is required to cast `ArrayAccess<string, Key>` to just an expected `array<string, Key>`.
         *
         * Can be removed once fixed in the JWT library.
         *
         * @var array<string, Key> $keySet
         */
        $keySet = $this->getGovUkSignInPublicKeys();

        $tokenClaims = (array)JWT::decode(
            $token,
            $keySet
        );

        if ($tokenClaims['iss']
            !== $this->getOpenIdConnectConfiguration('issuer')
        ) {
            throw new InvalidTokenException(
                'The Issuer of the ID token is invalid: '
                . $tokenClaims['iss'] . ' !== '
                . $this->getOpenIdConnectConfiguration('issuer')
            );
        }

        if ($tokenClaims['aud'] !== $this->clientId) {
            throw new InvalidTokenException(
                'The aud of the ID token is invalid: '
                . $tokenClaims['aud'] . ' !== ' . $this->clientId
            );
        }

        if ($nonce !== null && $tokenClaims['nonce'] !== $nonce) {
            throw new InvalidTokenException(
                'The nonce of the ID token is invalid: '
                . $tokenClaims['nonce'] . ' !== ' . $nonce
            );
        }

        // IAT, EXP, NBF are checked by JWT::decode();
        return $tokenClaims;
    }

    /**
     * {@inheritDoc}
     */
    public function getAccessToken(
        $grant,
        array $options = []
    ): \Dvsa\GovUkAccount\Token\AccessToken {
        $issuedAt = new DateTimeImmutable();
        $expiryDelta = $options['access_token_expiry_delta'] ??
            static::DEFAULT_ACCESS_TOKEN_EXPIRY;
        $expiresAt = $issuedAt->modify($expiryDelta);

        if (!$expiresAt instanceof DateTimeImmutable) {
            throw new \InvalidArgumentException('Could not create expiresAt using a delta on issuedAt.');
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

    protected function getAuthorizationParameters(array $options): array
    {
        $options = parent::getAuthorizationParameters($options);

        // Generate a nonce if not already set.
        if (empty($this->nonce)) {
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
    public function setNonce(string $nonce = null): string
    {
        if (empty($nonce)) {
            $nonce = $this->getRandomState();
        }
        $this->nonce = $nonce;

        return $this->nonce;
    }

    protected function getDefaultScopes(): array
    {
        return static::DEFAULT_SCOPES;
    }

    protected function getScopeSeparator(): string
    {
        return static::SCOPE_SEPARATOR;
    }

    protected function checkResponse(ResponseInterface $response, $data)
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

    protected function createAccessToken(
        array         $response,
        AbstractGrant $grant
    ): \Dvsa\GovUkAccount\Token\AccessToken {
        return new \Dvsa\GovUkAccount\Token\AccessToken($response, $this);
    }

    /**
     * @throws InvalidTokenException|\JsonException
     */
    protected function createResourceOwner(
        array       $response,
        AccessToken $token
    ): GovUkAccountUser {
        assert($token instanceof \Dvsa\GovUkAccount\Token\AccessToken);

        // If set, verify the claims for CoreIdentity
        $coreIdentityToken = $response[GovUkAccountUser::KEY_CLAIMS_CORE_IDENTITY] ?? null;
        if (!empty($coreIdentityToken)) {
            // Replace JWT with Validated Claim Array
            $response[GovUkAccountUser::KEY_CLAIMS_CORE_IDENTITY_DECODED] = $this->validateCoreIdentityClaim(
                $coreIdentityToken,
                $token->getIdTokenClaims()
            );
        }

        $encoded = json_encode($response);
        if (!$encoded) {
            throw new \JsonException('Could not encode $response');
        }

        $response = json_decode($encoded, true);
        if (!is_array($response)) {
            throw new \JsonException('Could not decode $response');
        }

        return new GovUkAccountUser($response);
    }

    /**
     * @throws InvalidTokenException
     */
    public function validateCoreIdentityClaim(
        string $token,
        array  $idTokenClaims
    ): array {

        $keys = $this->parseDidDocument(
            $this->core_identity_did_document_url
        );

        $claims = (array)JWT::decode(
            $token,
            $keys
        );

        $issuer = $claims['iss'] ?? null;
        if ($issuer !== $this->expectedCoreIdentityIssuer) {
            throw new InvalidTokenException(sprintf(
                'The issuer (iss) for CoreIdentityJWT is invalid: %s (expecting %s)',
                $issuer,
                $this->expectedCoreIdentityIssuer
            ));
        }

        $audience = $claims['aud'] ?? null;
        if ($audience !== $this->clientId) {
            throw new InvalidTokenException(sprintf(
                'The audience (aud) for CoreIdentityJWT is invalid: %s (expecting %s)',
                $audience,
                $this->clientId
            ));
        }

        $subject = $claims['sub'] ?? null;
        if ($subject !== $idTokenClaims['sub']) {
            throw new InvalidTokenException(sprintf(
                'The subject (sub) for CoreIdentityJWT is invalid and does not match the subject for the ID Token: %s (expecting %s)',
                $subject,
                $idTokenClaims['sub']
            ));
        }

        return $claims;
    }
}
