<?php
declare(strict_types=1);

namespace ZAuth\Core;

use PDO;

class Model {
    protected PDO $conn;

    public function __construct(PDO $conn) {
        $this->conn = $conn;
    }
}