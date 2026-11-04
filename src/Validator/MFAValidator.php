<?php
declare(strict_types=1);

namespace ZAuth\Validator;

use ZAuth\Exceptions\AuthException;

final class MFAValidator {
    public static function validate(array $data): array {
        $required_fields = [
            "code" => [
                "minLen" => 3,
                "maxLen" => 254,
                "type" => "email",
                "errorCode" => "INVALID_EMAIL"
            ],
            "password" => [
                "minLen" => 3,
                "maxLen" => 100,
                "type" => "string",
                "errorCode" => "INVALID_PASSWORD"
            ],
            "csrf_token" => [
                "minLen" => 1,
                "maxLen" => 128,
                "type" => "string",
                "errorCode" => "INVALID_CSRF_TOKEN"
            ],
            "captcha" => [
                "minLen" => 6,
                "maxLen" => 6,
                "type" => "string",
                "errorCode" => "INVALID_CAPTCHA"
            ]
        ];

        $payload = [];

        foreach ($required_fields as $name => $rules) {
            if (!array_key_exists($name, $data)) {
                throw new AuthException(
                    "$name field is required",
                    400,
                    "MISSING_FIELD"
                );
            }

            $field = $data[$name];

            if (!is_string($field)) {
                throw new AuthException(
                    "$name field must be a string",
                    400,
                    "INVALID_FIELD_TYPE"
                );
            }

            $normalizedField = $field;

            if (($rules['type'] ?? 'string') === 'email') {
                $normalizedField = trim($field);

                if ($normalizedField === '') {
                    throw new AuthException(
                        "$name field cannot be empty",
                        400,
                        $rules['errorCode']
                    );
                }

                if (!filter_var($normalizedField, FILTER_VALIDATE_EMAIL)) {
                    throw new AuthException(
                        "$name must be a valid email address",
                        400,
                        $rules['errorCode']
                    );
                }
            }

            $length = mb_strlen($normalizedField);

            if ($length < $rules['minLen']) {
                throw new AuthException(
                    "$name must be at least {$rules['minLen']} characters",
                    400,
                    $rules['errorCode']
                );
            }

            if ($length > $rules['maxLen']) {
                throw new AuthException(
                    "$name must not exceed {$rules['maxLen']} characters",
                    400,
                    $rules['errorCode']
                );
            }

            $payload[$name] = $normalizedField;
        }

        return [
            "email" => $payload['email'],
            "password" => $payload['password'],
            "csrf_token" => $payload['csrf_token'],
            "captcha" => $payload['captcha']
        ];
    }
}
