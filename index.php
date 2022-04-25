<?php

declare(strict_types=1);

require __DIR__ . '/bootstrap.php';

$path = parse_url($_SERVER["REQUEST_URI"], PHP_URL_PATH);

$parts = explode("/", $path);

$resource = $parts[1];

$action = strtolower($_SERVER['REQUEST_METHOD']);

if ($resource === 'login') {

    if (strtolower($action) === 'post') {
        $database = new Database($_ENV["DB_HOST"], $_ENV["DB_NAME"], $_ENV["DB_USER"], $_ENV["DB_PASS"]);

        $controller = new Controller($database);

        $data = json_decode(file_get_contents('php://input'), true);

        $controller->login($data);
    } else {
        http_response_code(422);
        echo json_encode(['error' => 'Method not allowed.']);
        exit;
    }
} else {
    http_response_code(404);
    echo json_encode(['message' => 'No found.']);
    exit;
}
