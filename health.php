<?php
header("Content-Type: application/json; charset=UTF-8");
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization");

if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') {
    http_response_code(200);
    exit();
}

try {
    // Test database connection
    require_once 'config.php';
    
    $response = [
        "status" => "healthy",
        "timestamp" => date('Y-m-d H:i:s'),
        "database" => "connected",
        "version" => "1.0.0",
        "environment" => getenv('APP_ENV') ?: 'development'
    ];
    
    echo json_encode($response);
    
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode([
        "status" => "unhealthy",
        "error" => $e->getMessage(),
        "timestamp" => date('Y-m-d H:i:s')
    ]);
}
?> 