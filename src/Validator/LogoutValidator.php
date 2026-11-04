<?php
declare(strict_types=1);

namespace ZAuth\Validator;

use ZAuth\Exceptions\AuthException;

final class LogoutValidator {
    public static function validate(array $data): array {
        if (!array_key_exists('csrf_token', $data)) {
            throw new AuthException(
                'csrf_token field is required',
                400,
                'MISSING_FIELD'
            );
        }

        $token = $data['csrf_token'];
        if (!is_string($token)) {
            throw new AuthException(
                'csrf_token field must be a string',
                400,
                'INVALID_FIELD_TYPE'
            );
        }

        if ($token === '' || mb_strlen($token) > 128) {
            throw new AuthException(
                'csrf_token must be between 1 and 128 characters',
                400,
                'INVALID_CSRF_TOKEN'
            );
        }

        return ['csrf_token' => $token];
    }
}
