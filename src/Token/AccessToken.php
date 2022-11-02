<?php

namespace Dvsa\GovUkSignInSdk\Token;

use Dvsa\GovUkSignInSdk\Exception\InvalidTokenException;
use Dvsa\GovUkSignInSdk\Provider\GovUkAccount;

class AccessToken extends \League\OAuth2\Client\Token\AccessToken
{
    protected string $idToken;
    protected array $idTokenClaims;
    protected array $tokenClaims;

    /**
     * @throws InvalidTokenException
     */
    public function __construct(array $options, GovUkAccount $provider)
    {
        parent::__construct($options);
        $this->tokenClaims = $provider->validateAccessToken($this->getToken());

        $this->idToken = $options['id_token'];
        unset($this->values['id_token']);
        $this->idTokenClaims = $provider->validateIdToken($this->idToken);
    }

    public function getIdToken(): string
    {
        return $this->idToken;
    }

    public function getIdTokenClaims(): array
    {
        return $this->idTokenClaims;
    }

    public function getTokenClaims(): array
    {
        return $this->tokenClaims;
    }

    /**
     * @inheritdoc
     */
    public function jsonSerialize()
    {
        $parameters = parent::jsonSerialize();

        if ($this->idToken) {
            $parameters['id_token'] = $this->idToken;
        }

        return $parameters;
    }
}