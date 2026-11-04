<?php
declare(strict_types=1);

namespace ZAuth\Core;

final class CSRF {
    public static function token(): string {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            throw new \RuntimeException("Session must be started");
        }

        if (empty($_SESSION['_csrf_token'])) {
            $_SESSION['_csrf_token'] = bin2hex(random_bytes(32));
        }

        return $_SESSION['_csrf_token'];
    }

    public static function validate(?string $token): bool {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            throw new \RuntimeException("Session must be started");
        }
        
        if (
            !is_string($token) ||
            $token === '' ||
            !isset($_SESSION['_csrf_token'])
        ) {
            return false;
        }

        return hash_equals($_SESSION['_csrf_token'], $token);
    }

    public static function regenerate(): void {
        $_SESSION['_csrf_token'] = bin2hex(random_bytes(32));
    }
}
