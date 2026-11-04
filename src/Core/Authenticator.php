<?php
declare(strict_types=1);

namespace ZAuth\Core;

use PDO;
use RuntimeException;
use Throwable;
use ZAuth\Exceptions\AuthException;
use ZAuth\Validator\LoginValidator;
use ZAuth\Validator\LogoutValidator;
use ZAuth\Models\LoginLog;
use ZAuth\Models\Users;
use ZAuth\Utils\Response;
use ZAuth\Utils\Security;
use ZAuth\Core\CAPTCHA;

final class Authenticator {
    private PDO $conn;

    public function __construct(PDO $conn) {
        $this->conn   = $conn;
    }

    public function login(array $payload) {
        try {
            $payload = LoginValidator::validate($payload);

            if (!CSRF::validate($payload['csrf_token'])) {
                return Response::json(
                    [
                        'message'    => "Missing or incorrect csrf token",
                        'error_code' => "INVALID_CSRF_TOKEN",
                    ], false, 403
                );
            }

            if ($this->isLoggedIn()) {
                return Response::json(
                    [
                        'message'     => "Already logged in",
                        'status_code' => "AUTHENTICATED"
                    ], true, 200
                );
            }

            $security = new Security($this->conn);
            $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

            if (!CAPTCHA::verify($payload['captcha'])) {
                $security->loginLog($ip, $payload['email'], 3);

                return Response::json(
                    [
                        'message'    => "Incorrect or expired CAPTCHA",
                        'error_code' => "INVALID_CAPTCHA",
                    ], false, 400
                );
            }

            $user = (new Users($this->conn))->findByEmail($payload['email']);

            if (!$user) {
                return Response::json(
                    [
                        'message'    => "Incorrect userid or password",
                        'error_code' => "INVALID_CREDENTIALS",
                    ], false, 401
                );
            }

            if ($security->isBlockedIP($ip)) {
                return Response::json(
                    [
                        'message'    => "Your IP address has been blocked! Contact Admin.",
                        'error_code' => "IP_ADDR_BLOCKED",
                    ], false, 403
                );
            }

            if ($security->isBreach($ip)) {
                $security->blockIP($ip);

                return Response::json(
                    [
                        'message'    => "Your IP address has been blocked! Contact Admin.",
                        'error_code' => "IP_ADDR_BLOCKED",
                    ], false, 403
                );
            }

            if ($user['IPSEC'] == 1 && !$security->isAllowedIP($ip, $user['ID'])) {
                $security->loginLog($ip, $payload['email'], 3);

                return Response::json(
                    [
                        'message'    => "You are not allowed to login",
                        'error_code' => "IP_ADDR_NOT_ALLOWED",
                    ], false, 401
                );
            }

            if (!password_verify($payload['password'], $user['PWDHASH'])) {
                $security->loginLog($ip, $payload['email'], 3);
                
                return Response::json(
                    [
                        'message'    => "Incorrect userid or password",
                        'error_code' => "INVALID_CREDENTIALS",
                    ], false, 401
                );
            }

            if ($user['MFA'] === 0){
                session_regenerate_id(true);
                $_SESSION['csrf_token'] = CSRF::token();		
                $_SESSION['SESSUID'] = $user['ID'];
                $_SESSION['SESSBID'] = $user['BID'];
                $_SESSION['SESSUNAME'] = $user['NAME'];
                $_SESSION['SESSCAT'] = $user['CAT'];
                $_SESSION['SESSPICNAME'] = $user['PICPATH1'];			
                $_SESSION['SESSLOGINID'] = $payload['email'];
                $_SESSION['SESSMLOGID'] = $security->loginLog($ip, $payload['email'], 1);
                
                $now = time();
                $_SESSION['MFA_ENABLED'] = false;
                $_SESSION['MFA_VERIFIED'] = false;
                $_SESSION['SESSLVERSION'] = (int) $user['LVERSION'] + 1;
                $_SESSION['AUTH_TIME']    = $now;
                $_SESSION['LAST_ACTIVITY'] = $now;
                                
                try {
                    (new Users($this->conn))->incrementLoginVersion((int) $user['ID']);
                } 
                catch (Throwable $e) {
                    error_log('User update for user ID: ' . $user['ID']);
                    return Response::json([
                        'message' => "User was not updated"
                    ], false, 500);
                }
                
                return Response::json([
                    'status_code' => "AUTHENTICATED"
                ], true, 200);
            } else {
                $_SESSION['SESSLOGINID'] = $payload['email'];			

                return Response::json([
                    'status_code' => "MFA_REQUIRED",
                    'mfa_methods' => ['email']
                ], true, 200);
            }
        } catch (AuthException $e) {
            return Response::json(
                [
                    'message'    => $e->getMessage(),
                    'error_code' => $e->getErrorCode(),
                ], false, $e->getStatusCode()
            );
        } catch (RuntimeException $e) {
            return Response::json(
                [
                    'message'    => $e->getMessage(),
                    'error_code' => "SERVER_ERROR",
                ], false, 500
            );
        }
    }

    public function isLoggedIn(): bool {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            return false;
        }

        $userId = filter_var(
            $_SESSION['SESSUID'] ?? null,
            FILTER_VALIDATE_INT,
            ['options' => ['min_range' => 1]]
        );
        $loginVersion = filter_var(
            $_SESSION['SESSLVERSION'] ?? null,
            FILTER_VALIDATE_INT,
            ['options' => ['min_range' => 1]]
        );

        if ($userId === false || $loginVersion === false) {
            return false;
        }

        return (new Users($this->conn))->hasLoginVersion(
            $userId,
            $loginVersion
        );
    }

    public function logout(array $payload) {
        try {
            $payload = LogoutValidator::validate($payload);

            if (!CSRF::validate($payload['csrf_token'])) {
                return Response::json(
                    [
                        'message'    => "Missing or incorrect csrf token",
                        'error_code' => "INVALID_CSRF_TOKEN",
                    ], false, 403
                );
            }

            if (!$this->isLoggedIn()) {
                return Response::json(
                    [
                        'message'    => "You must login first",
                        'error_code' => "LOGIN_REQUIRED",
                    ], false, 401
                );
            }

            $loginLogId = filter_var(
                $_SESSION['SESSMLOGID'] ?? null,
                FILTER_VALIDATE_INT
            );

            if ($loginLogId !== false && $loginLogId !== null && $loginLogId > 0) {
                try {
                    (new LoginLog($this->conn))->markLoggedOut($loginLogId);
                } catch (Throwable $e) {
                    error_log(
                        'Logout audit update failed for login log ID: '
                        . $loginLogId
                    );
                }
            }

            $_SESSION = [];

            if (ini_get('session.use_cookies')) {
                $params = session_get_cookie_params();

                setcookie(session_name(), '', [
                    'expires'  => time() - 42000,
                    'path'     => $params['path'],
                    'domain'   => $params['domain'],
                    'secure'   => $params['secure'],
                    'httponly' => $params['httponly'],
                    'samesite' => $params['samesite'] ?? 'Lax',
                ]);
            }

            session_destroy();

            return Response::json([
                'status_code' => "LOGGED_OUT"
            ], true, 200);
        } catch (AuthException $e) {
            return Response::json(
                [
                    'message'    => $e->getMessage(),
                    'error_code' => $e->getErrorCode(),
                ], false, $e->getStatusCode()
            );
        } catch (RuntimeException $e) {
            return Response::json(
                [
                    'message'    => $e->getMessage(),
                    'error_code' => "SERVER_ERROR",
                ], false, 500
            );
        }
    }
}
