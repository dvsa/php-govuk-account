<?php

namespace Dvsa\GovUkAccount\Token;

use JsonSerializable;
use League\OAuth2\Client\Provider\ResourceOwnerInterface;

class GovUkAccountUser implements ResourceOwnerInterface, JsonSerializable
{
    public const KEY_CLAIMS_CORE_IDENTITY = 'https://vocab.account.gov.uk/v1/coreIdentityJWT';
    public const KEY_CLAIMS_CORE_IDENTITY_DECODED = 'https://vocab.account.gov.uk/v1/coreIdentityDecoded';

    public function __construct(protected array $data)
    {
    }

    public function getId()
    {
        return $this->getField('id') ??
            $this->getField('sub') ?? $this->getField('subject') ?? null;
    }

    /**
     * @return mixed|null
     */
    public function getField(string $key)
    {
        return $this->data[$key] ?? null;
    }

    #[\ReturnTypeWillChange]
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }

    public function toArray(): array
    {
        return $this->data;
    }
}
