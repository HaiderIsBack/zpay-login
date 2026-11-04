<?php
declare(strict_types=1);

namespace ZAuth\Core;

final class CAPTCHA {
    public static function verify(mixed $pin): bool {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            throw new \RuntimeException('Session must be started');
        }

        $hash = $_SESSION['CAPTCHAPIN'] ?? null;
        unset($_SESSION['CAPTCHAPIN']);

        return is_string($pin)
            && is_string($hash)
            && password_verify(trim($pin), $hash);
    }

    public static function generate(): void {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            throw new \RuntimeException('Session must be started');
        }

        $font = dirname(__DIR__, 2) . '/public/assets/font/Codystar-Regular.ttf';

        if (!extension_loaded('gd') || !function_exists('imagettftext')) {
            throw new \RuntimeException('GD with FreeType support is required to generate CAPTCHA images');
        }

        if (!is_readable($font)) {
            throw new \RuntimeException('CAPTCHA font is missing or unreadable');
        }

        $pin = (string) random_int(100000, 999999);
        $_SESSION['CAPTCHAPIN'] = password_hash($pin, PASSWORD_ARGON2ID);

        $image = imagecreatetruecolor(150, 50);
        $backgroundColor = imagecolorallocate($image, 255, 255, 255);
        $textColor = imagecolorallocate($image, 0, 0, 0);
        $lineColor = imagecolorallocate($image, 185, 185, 185);

        imagefill($image, 0, 0, $backgroundColor);
        imageline($image, 0, 0, 130, 50, $lineColor);
        imageline($image, 0, 50, 130, 0, $lineColor);
        imageline($image, 65, 0, 65, 50, $lineColor);
        imageline($image, 0, 25, 130, 25, $lineColor);
        imageline($image, 0, 25, 130, 30, $lineColor);

        if (imagettftext($image, 24, 15, 10, 40, $textColor, $font, $pin) === false) {
            imagedestroy($image);
            throw new \RuntimeException('Unable to render CAPTCHA text');
        }

        header('Content-Type: image/png');
        header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
        header('X-Content-Type-Options: nosniff');

        if (!imagepng($image)) {
            imagedestroy($image);
            throw new \RuntimeException('Unable to generate CAPTCHA image');
        }

        imagedestroy($image);
    }
}