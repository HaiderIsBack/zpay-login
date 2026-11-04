<?php
declare(strict_types=1);

namespace ZAuth\MFA;

use Throwable;
use ZAuth\Utils\Response;

final class MFA {
    public static function verify(array $payload): string {
        try {
            return Response::json([], true, 200);
        } catch (Throwable $e) {
            return Response::json(
                [
                    'message'    => $e->getMessage(),
                    'error_code' => "SERVER_ERROR",
                ],
                false,
                500
            );
        }
    }
}
