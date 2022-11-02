<?php

namespace Dvsa\GovUkSignInSdk\Provider;

use JsonSerializable;
use League\OAuth2\Client\Provider\ResourceOwnerInterface;

class GovUkAccountUser implements ResourceOwnerInterface, JsonSerializable
{
    public const KEY_CLAIMS_CORE_IDENTITY = 'https://vocab.account.gov.uk/v1/coreIdentityJWT';

    protected array $data = [];

    public function __construct(array $data)
    {
        $this->data = $data;
    }

    public function getId()
    {
        return $this->getField('id') ??
            $this->getField('sub') ?? $this->getField('subject') ?? null;
    }

    /**
     * @param  string  $key
     *
     * @return mixed|null
     */
    public function getField(string $key)
    {
        return $this->data[$key] ?? null;
    }

    public function jsonSerialize()
    {
        return $this->toArray();
    }

    public function toArray(): array
    {
        return $this->data;
    }
}