<?php

namespace Dvsa\GovUkSignInSdk\Exception;

use Throwable;

class ApiException extends GovUkAccountException
{
    public array $data;

    public function __construct(
        string $message = "",
        int $code = 0,
        Throwable $previous = null,
        array $data = []
    ) {
        $this->data = $data;
        parent::__construct($message, $code, $previous);
    }
}