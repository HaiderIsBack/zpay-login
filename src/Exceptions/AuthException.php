<?php
declare(strict_types=1);

namespace ZAuth\Exceptions;

use Exception;

class AuthException extends Exception {
    private int $statusCode;
    private string $errorCode;

    public function __construct(
        string $message,
        int $statusCode = 400,
        string $errorCode = "BAD_REQUEST"
    ) {
        parent::__construct($message);

        $this->statusCode = $statusCode;
        $this->errorCode = $errorCode;
    }

    public function getStatusCode(): int {
        return $this->statusCode;
    }

    public function getErrorCode(): string {
        return $this->errorCode;
    }
}
