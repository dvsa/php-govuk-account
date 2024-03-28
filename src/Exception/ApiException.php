<?php

namespace Dvsa\GovUkAccount\Exception;

use Throwable;

class ApiException extends GovUkAccountException
{
    public function __construct(
        string    $message = '',
        int       $code = 0,
        Throwable $previous = null,
        public array     $data = []
    ) {
        parent::__construct($message, $code, $previous);
    }
}
