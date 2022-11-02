<?php

namespace Dvsa\GovUkAccount\Provider;

use ArrayAccess;
use DateTimeImmutable;
use Dvsa\GovUkSignInSdk\Exception\ApiException;
use Dvsa\GovUkSignInSdk\Exception\InvalidTokenException;
use Exception;
use Firebase\JWT\CachedKeySet;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Psr7\HttpFactory;
use Illuminate\Support\Collection;
use InvalidArgumentException;
use League\OAuth2\Client\Grant\AbstractGrant;
use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Tool\BearerAuthorizationTrait;
use Psr\Cache\CacheItemPoolInterface;
use Psr\Http\Client\ClientInterface;
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
    protected array $openIdConnectConfiguration;

    protected ?ArrayAccess $govUkSignInPublicKeys;
    protected Key $govUkSignInIdentityPublicKey;

    protected ?CacheItemPoolInterface $cache = null;

    use BearerAuthorizationTrait;

    public function __construct(
        array $options = [],
        array $collaborators = [],
        CacheItemPoolInterface $cache = null
    ) {
        parent::__construct($options, $collaborators);

        $this->clientId = $options['client_id'];
        $this->algorithm = $options['keys']['algorithm'];
        $this->privateKey = base64_decode($options['keys']['private_key']);
        $this->loggedInUrl
            = $this->redirectUri = $options['redirect_uri']['logged_in'];
        $this->expectedCoreIdentityIssuer
            = $options['expected_core_identity_issuer'];
        $this->cache = $cache;
        $this->openIdConnectConfigurationUrl = $options['discovery_endpoint'];

        // TODO: Remove when key is available in .well-known/jwks.json
        $this->govUkSignInIdentityPublicKey
            = $this->parseIdentityAssuranceKey(
            $options['keys']['identity_assurance_public_key']
        );
    }

    /**
     * Parses a JWK in array format, returning a Key object or throwing an exception.
     *
     * @param  array|string  $jwk  JWK - Will attempt to parse string as JSON.
     *
     * @return Key
     */
    private function parseIdentityAssuranceKey($jwk): Key
    {
        if ( ! is_array($jwk)) {
            $jwk = json_decode($jwk);
        }

        $key = JWK::parseKey($jwk);
        if (empty($key)) {
            throw new InvalidArgumentException(
                "Unable to create KEY object from identity_assurance_public_key"
            );
        }

        return $key;
    }

    /**
     * Sets the state used for GOV.UK Account integration; state is replayed when redirected back to service.
     *
     * Note: Not specifying or empty($state) results in setting a randomly generated one.
     *
     * @param  string|null  $state
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
     * @return mixed
     * @throws ApiException
     * @throws GuzzleException
     */
    protected function getOpenIdConnectConfiguration(string $key)
    {
        if ( ! isset($this->openIdConnectConfiguration)) {
            $this->openIdConnectConfiguration
                = $this->loadOpenIdConnectConfiguration();
        }

        if ( ! array_key_exists($key, $this->openIdConnectConfiguration)) {
            throw new InvalidArgumentException(
                "Cannot find {$key} in openIdConnectConfiguration"
            );
        }

        return $this->openIdConnectConfiguration[$key];
    }

    /**
     * @throws ApiException
     * @throws GuzzleException
     */
    private function loadOpenIdConnectConfiguration(): array
    {
        $response = $this->getHttpClient()->request(
            'GET',
            $this->openIdConnectConfigurationUrl
        );
        if ($response->getStatusCode() !== 200) {
            throw new ApiException(
                'Error loading OpenID Connect Configuration',
                $response->getStatusCode(), null, [$response]
            );
        }

        return $this->parseResponse($response);
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
                .$tokenClaims['iss'].' !== '
                .$this->getOpenIdConnectConfiguration('issuer')
            );
        }

        if ($tokenClaims['client_id'] !== $this->clientId) {
            throw new InvalidTokenException(
                'The client_id of the access token is invalid: '
                .$tokenClaims['client_id'].' !== '.$this->clientId
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
        if ( ! isset($this->govUkSignInPublicKeys)) {
            $this->govUkSignInPublicKeys
                = $this->loadJwks(
                $this->getOpenIdConnectConfiguration('jwks_uri')
            );
        }

        return $this->govUkSignInPublicKeys;
    }

    /**
     * @throws ApiException
     * @throws GuzzleException
     */
    public function loadJwks(string $jwksUrl): ArrayAccess
    {
        if ($this->cache instanceof CacheItemPoolInterface) {
            $httpClient = $this->getHttpClient();
            assert($httpClient instanceof ClientInterface);

            return new CachedKeySet(
                $jwksUrl,
                $httpClient,
                new HttpFactory(),
                $this->cache
            );
        }

        $response = $this->getHttpClient()->request('GET', $jwksUrl);
        if ($response->getStatusCode() !== 200) {
            throw new ApiException(
                'Error loading JWKs',
                $response->getStatusCode(), null, [$response]
            );
        }

        $parsed = $this->parseResponse($response);

        return new Collection(JWK::parseKeySet($parsed));
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
                .$tokenClaims['iss'].' !== '
                .$this->getOpenIdConnectConfiguration('issuer')
            );
        }

        if ($tokenClaims['aud'] !== $this->clientId) {
            throw new InvalidTokenException(
                'The aud of the ID token is invalid: '
                .$tokenClaims['aud'].' !== '.$this->clientId
            );
        }

        if ($nonce !== null && $tokenClaims['nonce'] !== $nonce) {
            throw new InvalidTokenException(
                'The nonce of the ID token is invalid: '
                .$tokenClaims['nonce'].' !== '.$nonce
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
    ): \Dvsa\GovUkSignInSdk\Token\AccessToken {
        $issuedAt = new DateTimeImmutable();
        $expiryDelta = $options['access_token_expiry_delta'] ??
            static::DEFAULT_ACCESS_TOKEN_EXPIRY;
        $expiresAt = $issuedAt->modify($expiryDelta);

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
        assert($accessToken instanceof \Dvsa\GovUkSignInSdk\Token\AccessToken);

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
     * @param  string|null  $nonce
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
                $response->getStatusCode(), null, [$response, $data]
            );
        }
    }

    protected function createAccessToken(
        array $response,
        AbstractGrant $grant
    ): \Dvsa\GovUkSignInSdk\Token\AccessToken {
        return new \Dvsa\GovUkSignInSdk\Token\AccessToken($response, $this);
    }

    /**
     * @throws InvalidTokenException
     */
    protected function createResourceOwner(
        array $response,
        AccessToken $token
    ): GovUkAccountUser {
        assert($token instanceof \Dvsa\GovUkSignInSdk\Token\AccessToken);

        // If set, verify the claims for CoreIdentity
        $coreIdentityToken
            = $response[GovUkAccountUser::KEY_CLAIMS_CORE_IDENTITY] ?? null;
        if ( ! empty($coreIdentityToken)) {
            // Replace JWT with Validated Claim Array
            $response[GovUkAccountUser::KEY_CLAIMS_CORE_IDENTITY]
                = $this->validateCoreIdentityClaim(
                $coreIdentityToken,
                $token->getIdTokenClaims()
            );
        }

        return new GovUkAccountUser($response);
    }

    /**
     * @throws InvalidTokenException
     */
    public function validateCoreIdentityClaim(
        string $token,
        array $idTokenClaims
    ): array {
        $claims = (array)JWT::decode(
            $token,
            $this->govUkSignInIdentityPublicKey
        );

        $issuer = $claims['iss'] ?? null;
        if ($issuer !== $this->expectedCoreIdentityIssuer) {
            throw new InvalidTokenException(
                'The issuer for CoreIdentityJWT is invalid: '
                .$issuer.' (expecting '.$this->expectedCoreIdentityIssuer.')'
            );
        }

        $subject = $claims['sub'] ?? null;
        if ($subject !== $idTokenClaims['sub']) {
            throw new InvalidTokenException(
                'The subject for CoreIdentityJWT is invalid and does not match the subject for the ID Token: '
                .$subject.' (expecting '.$idTokenClaims['sub'].')'
            );
        }

        return $claims;
    }
}
