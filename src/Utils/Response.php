<?php
declare(strict_types=1);

namespace ZAuth\Utils;

final class Response {
    public static function json(mixed $data, bool $success = true, int $code = 200) {
        return json_encode([
            'success' => $success,
            'data'    => $data,
            'code'    => $code
        ]);
    }

    public static function redirect(string $path) {
        header("Location: " . $path);
        exit;
    }
}
