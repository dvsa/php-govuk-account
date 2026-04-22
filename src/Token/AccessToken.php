<?php

declare(strict_types=1);

namespace Dvsa\GovUkAccount\Token;

use Dvsa\GovUkAccount\Exception\ApiException;
use Dvsa\GovUkAccount\Exception\InvalidTokenException;
use Dvsa\GovUkAccount\Provider\GovUkAccount;
use InvalidArgumentException;

class AccessToken extends \League\OAuth2\Client\Token\AccessToken
{
    protected string $idToken;

    /** @var array<string, mixed> */
    protected array $idTokenClaims;

    /** @var array<string, mixed> */
    protected array $tokenClaims;

    /**
     * @param array<string, mixed> $options
     *
     * @throws InvalidTokenException
     * @throws ApiException
     * @throws InvalidArgumentException When the response is missing the `id_token` field.
     */
    public function __construct(array $options, GovUkAccount $provider)
    {
        parent::__construct($options);
        $this->tokenClaims = $provider->validateAccessToken($this->getToken());

        $idToken = $options['id_token'] ?? null;
        if (!is_string($idToken) || $idToken === '') {
            throw new InvalidArgumentException('Token response is missing required "id_token" string');
        }

        $this->idToken = $idToken;
        unset($this->values['id_token']);
        $this->idTokenClaims = $provider->validateIdToken($this->idToken);
    }

    public function getIdToken(): string
    {
        return $this->idToken;
    }

    /**
     * @return array<string, mixed>
     */
    public function getIdTokenClaims(): array
    {
        return $this->idTokenClaims;
    }

    /**
     * @return array<string, mixed>
     */
    public function getTokenClaims(): array
    {
        return $this->tokenClaims;
    }

    /**
     * @return array<array-key, mixed>
     */
    public function jsonSerialize(): array
    {
        $parameters = parent::jsonSerialize();

        if ($this->idToken !== '') {
            $parameters['id_token'] = $this->idToken;
        }

        return $parameters;
    }
}
