<?php

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
            $token = $jwt->encode(['sub' => $admin['id']]);
            $this->respondCreated($token);
        } else {
            $this->respondNotAuthorized();
        }
    }


    protected function respondCreated(string $token): void
    {
        http_response_code(200);
        echo json_encode(['a_t' => $token]);
        exit;
    }

    protected function respondNotAuthorized()
    {
        http_response_code(401);
        echo json_encode(["message" => 'no authorized.']);
        exit;
    }
}
