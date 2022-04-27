<?php

use Auth\Jwt;

class Controller
{
    protected $errors = [];
    protected PDO $connection;

    public function __construct(private Database $databse)
    {
        $this->connection = $this->databse->getConnection();
    }
    public function login(array $data)
    {
        if (!isset($data['email']) || !isset($data['password'])) {
            $this->respondNotAuthorized();
        }

        $sql = "SELECT * FROM admins WHERE email = :email LIMIT 1";
        $stmt = $this->connection->prepare($sql);
        $stmt->bindValue(':email', $data['email']);
        $stmt->execute();

        $admin = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($admin !== false && password_verify($data['password'], $admin['password'])) {
            $jwt = new Jwt($_ENV['SECRET_KEY']);
            $refreshTokenExpiry = time() + 432000;
            $accessToken = $jwt->encode(['sub' => $admin['id'], 'exp' => time() + 300]);
            $refreshToken = $jwt->encode(['sub' => $admin['id'], 'exp' => $refreshTokenExpiry]);
            $this->saveRefreshToken($refreshToken, $refreshTokenExpiry);
            $this->respondOk($accessToken, $refreshToken);
        } else {
            $this->respondNotAuthorized();
        }
    }

    public function getById(int $id): array | false
    {
        $sql = "SELECT * FROM admins WHERE id = :id LIMIT 1";
        $stmt = $this->connection->prepare($sql);
        $stmt->bindValue(':id', $id);
        $stmt->execute();

        return $stmt->fetch(PDO::FETCH_ASSOC);
    }

    public function getByToken(string $token): array | false
    {
        $hash = hash_hmac("sha256", $token, $_ENV['SECRET_KEY']);

        $sql = "SELECT * FROM refresh_token WHERE token_hash = :hash LIMIT 1";
        $stmt = $this->connection->prepare($sql);
        $stmt->bindValue(':hash', $hash);
        $stmt->execute();

        return $stmt->fetch(PDO::FETCH_ASSOC);
    }

    public function saveRefreshToken(string $refreshToken, int $refreshTokenExpiry): bool
    {
        $hash = hash_hmac("sha256", $refreshToken, $_ENV['SECRET_KEY']);
        $sql = "INSERT INTO refresh_token (token_hash, expires_at)VALUES(:token_hash, :token_expity)";
        $stmt = $this->connection->prepare($sql);

        $stmt->bindValue(':token_hash', $hash);
        $stmt->bindValue(':token_expity', $refreshTokenExpiry);

        return $stmt->execute();
    }

    public function deleteRefreshToken(string $token): int
    {
        $hash = hash_hmac("sha256", $token, $_ENV['SECRET_KEY']);
        $sql = "DELETE FROM refresh_token WHERE  token_hash = :hash";
        $stmt = $this->connection->prepare($sql);
        $stmt->bindValue(':hash', $hash);
        $stmt->execute();
        return $stmt->rowCount();
    }


    protected function respondOk(string $accessToken, string $refreshToken): void
    {
        http_response_code(200);
        echo json_encode(['a_t' => $accessToken, 'r_t' => $refreshToken]);
        exit;
    }

    protected function respondNotAuthorized()
    {
        http_response_code(401);
        echo json_encode(["message" => 'No authorized.']);
        exit;
    }
}
