<?php
declare(strict_types=1);

namespace ZAuth\Utils;

use PDO;

final class Security {
    private PDO $conn;

    public function __construct(PDO $conn) {
        $this->conn = $conn;
    }

    public function isBlockedIP(string $ip) {
		$ip_pton = inet_pton($ip);

        $stmt = $this->conn->prepare("
            SELECT 1 FROM ipblock 
            WHERE STARTIP <= ? AND ENDIP >= ?
			AND ETIME >= NOW() - INTERVAL 5 MINUTE
            LIMIT 1
        ");
		$stmt->execute([$ip_pton, $ip_pton]);
        return (bool)$stmt->fetch();
    }

    public function isAllowedIP(string $ip, int $userId)  {
		$ip_pton = inet_pton($ip);

        $stmt = $this->conn->prepare("
            SELECT 1 FROM iprange 
            WHERE MEMID = ?
            AND STARTIP <= ? AND ENDIP >= ?
            LIMIT 1
        ");
        $stmt->execute([$userId, $ip_pton, $ip_pton]);
		
        return (bool)$stmt->fetch();
    }

    // public function isValidHost() {
    //     return in_array($_SERVER['HTTP_HOST'] ?? '', $this->allowedHosts, true);
    // }

    public function isBreach(string $ip) {
		$ip_pton = inet_pton($ip);

        $stmt = $this->conn->prepare("
            SELECT COUNT(*) FROM log_login
            WHERE STATUS = 3
            AND IPADDRESS = ?
            AND INTIME >= NOW() - INTERVAL 30 MINUTE
        ");
		$stmt->execute([$ip_pton]);
        return $stmt->fetchColumn() > 5;
    }

    public function blockIP(string $ip) {
		$ip_pton = inet_pton($ip);

        $stmt = $this->conn->prepare("
            INSERT INTO ipblock (STARTIP, ENDIP, ETIME)
            VALUES (?, ?, NOW() )
        ");
		$stmt->execute([$ip_pton, $ip_pton]);
    }

    public function loginLog(string $ip, string $user, int $status) {
		$ip_pton = inet_pton($ip);
		
        $stmt = $this->conn->prepare("
            INSERT INTO log_login (TYPE, USERID, IPADDRESS, URL, INTIME, STATUS)
            VALUES (?, ?, ?, ?, NOW(), ?)
        ");
		$stmt->execute([1, $user, $ip_pton, $_SERVER['HTTP_HOST'], $status ]);
        
		return $this->conn->lastInsertId();
    }
}
