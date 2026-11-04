<?php
declare(strict_types=1);

namespace ZAuth\Models;

use PDO;
use RuntimeException;
use ZAuth\Core\Model;

final class Users extends Model {
    public function __construct(PDO $conn) {
        parent::__construct($conn);
    }

    public function findByEmail(string $email) {
        $stmt = $this->conn->prepare(
            "SELECT u.*, m.`KEY` AS __meta_key, m.`VALUE` AS __meta_value
            FROM (
                SELECT * FROM users WHERE EMAIL = ? AND STATUS = 1 LIMIT 1
            ) AS u
            LEFT JOIN users_meta AS m ON u.ID = m.USER_ID"
        );
        $stmt->execute([$email]);

        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
        if ($rows === []) {
            return false;
        }

        $user = $rows[0];
        unset($user['__meta_key'], $user['__meta_value']);

        foreach ($rows as $row) {
            if ($row['__meta_key'] !== null) {
                $user[$row['__meta_key']] = $row['__meta_value'];
            }
        }

        return $user;
    }

    public function incrementLoginVersion(int $userId): void {
        $stmt = $this->conn->prepare(
            'UPDATE users
            SET LVERSION = COALESCE(LVERSION, 0) + 1
            WHERE ID = ?
            LIMIT 1'
        );
        $stmt->execute([$userId]);

        if ($stmt->rowCount() !== 1) {
            throw new RuntimeException('Target user was not updated');
        }
    }

    public function hasLoginVersion(int $userId, int $loginVersion): bool {
        $stmt = $this->conn->prepare(
            'SELECT 1
            FROM users
            WHERE ID = ?
                AND STATUS = 1
                AND COALESCE(LVERSION, 0) = ?
            LIMIT 1'
        );
        $stmt->execute([$userId, $loginVersion]);

        return $stmt->fetchColumn() !== false;
    }
}