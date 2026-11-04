<?php
declare(strict_types=1);

namespace ZAuth\Models;

use PDO;
use ZAuth\Core\Model;

final class LoginLog extends Model {
    public function __construct(PDO $conn) {
        parent::__construct($conn);
    }

    public function markLoggedOut(int $loginLogId): void {
        $stmt = $this->conn->prepare(
            'UPDATE log_login
            SET STATUS = ?, OUTTIME = NOW()
            WHERE ID = ?
            LIMIT 1'
        );
        $stmt->execute([2, $loginLogId]);
    }
}
