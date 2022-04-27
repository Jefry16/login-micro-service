<?php

declare(strict_types=1);

use Auth\Jwt;

require __DIR__ . '/bootstrap.php';

$path = parse_url($_SERVER["REQUEST_URI"], PHP_URL_PATH);

$parts = explode("/", $path);

$resource = $parts[1];

$action = strtolower($_SERVER['REQUEST_METHOD']);

if (($resource === 'login' || $resource === 'refresh' || $resource === 'logout') && $action === 'post') {

    $database = new Database($_ENV["DB_HOST"], $_ENV["DB_NAME"], $_ENV["DB_USER"], $_ENV["DB_PASS"]);
    $controller = new Controller($database);

    if ($resource === 'login') {

        $data = json_decode(file_get_contents('php://input'), true);

        $controller->login($data);
    } elseif ($resource === 'refresh') {
        $data = json_decode(file_get_contents('php://input'), true);
        if (!array_key_exists('token', $data)) {
            http_response_code(400);
            echo json_encode(['message' => 'Missing token.']);
            exit;
        }
        $jwt = new Jwt($_ENV['SECRET_KEY']);
        try {
            $payload = $jwt->decode($data['token']);
        } catch (Exception) {
            http_response_code(400);
            echo json_encode(['message' => 'Invalid token.']);
            exit;
        }
        $admin = $controller->getById($payload['sub']);

        if ($admin === false) {
            http_response_code(401);
            echo json_encode(['message' => 'Invalid authentication.']);
            exit;
        }
        $payload = ['sub' => $admin['id'], 'exp' => time() + 300];
        $tokenExpiry = time() + 432000;
        $accessToken = $jwt->encode($payload);
        $refreshToken = $jwt->encode(['sub' => $admin['id'],  'exp' => $tokenExpiry]);

        $oldToken = $controller->getByToken($data['token']);

        if ($oldToken === false) {
            http_response_code(400);
            echo json_encode(['message' => 'Invalid token (not on whitelist).']);
            exit;
        }

        $controller->deleteRefreshToken($data['token']);
        $controller->saveRefreshToken($refreshToken, $tokenExpiry);
        echo json_encode(['a_t' => $accessToken, 'r_t' => $refreshToken]);
    } else {
        $data = json_decode(file_get_contents('php://input'), true);
        if (isset($data['token'])) {

            $controller->deleteRefreshToken($data['token']);
        }
    }
} else {
    http_response_code(404);
    echo json_encode(['message' => 'No found.']);
    exit;
}
