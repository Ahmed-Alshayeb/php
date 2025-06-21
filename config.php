<?php
// ============ Configuration File ============

// Include JWT helper
require_once __DIR__ . '/jwt_helper.php';

// Load environment variables
if (file_exists(__DIR__ . '/.env')) {
    $env = parse_ini_file(__DIR__ . '/.env');
    foreach ($env as $key => $value) {
        putenv("$key=$value");
        $_ENV[$key] = $value;
    }
}

// Timezone settings
date_default_timezone_set(getenv('APP_TIMEZONE') ?: 'Africa/Cairo');

// Database configuration - SERVER DATABASE CONNECTION
$servername = getenv('DB_HOST') ?: 'localhost';
$username   = getenv('DB_USER') ?: 'root';
$password   = getenv('DB_PASS') ?: '';
$dbname     = getenv('DB_NAME') ?: 'medical_care_db';
$dbport     = getenv('DB_PORT') ?: 3306;

// JWT settings
$jwt_secret = getenv('JWT_SECRET') ?: 'd691a2d924d38287b699ce1d3023315dff85839b10e5424f02f9db79e59f6a3b';
$jwt_expiry = getenv('JWT_EXPIRY') ?: 3600;

// CORS settings - Update with your Flutter app domains
$allowed_origins = explode(',', getenv('ALLOWED_ORIGINS') ?: 'http://localhost:3000,http://localhost:8080,http://localhost:8000');

// Rate limiting configuration
$rate_limit = [
    'requests'     => getenv('RATE_LIMIT_REQUESTS') ?: 100,
    'time_window'  => getenv('RATE_LIMIT_WINDOW') ?: 3600
];

// Cache configuration
$cache_settings = [
    'enabled'  => getenv('CACHE_ENABLED') ?: true,
    'duration' => getenv('CACHE_DURATION') ?: 3600
];

// Database connection with improved error handling
try {
    // Create connection with port specification
    $conn = new mysqli($servername, $username, $password, $dbname, $dbport);
    
    if ($conn->connect_error) {
        throw new Exception("Database connection failed: " . $conn->connect_error);
    }
    
    // Set charset and timezone
    $conn->set_charset("utf8mb4");
    $conn->query("SET time_zone = '+02:00'");
    
    // Test connection
    if (!$conn->ping()) {
        throw new Exception("Database server is not responding");
    }
    
} catch (Exception $e) {
    error_log("Database connection error: " . $e->getMessage());
    http_response_code(500);
    die(json_encode([
        "error" => "Database connection failed",
        "message" => "Please check your database configuration",
        "details" => getenv('APP_ENV') === 'development' ? $e->getMessage() : null
    ]));
}

// Utility functions

// Input sanitization
function validateInput($data) {
    if (is_array($data)) {
        return array_map('validateInput', $data);
    }
    return htmlspecialchars(stripslashes(trim($data)), ENT_QUOTES, 'UTF-8');
}

// Email validation
function validateEmail($email) {
    return filter_var($email, FILTER_VALIDATE_EMAIL);
}

// Password hashing
function hashPassword($password) {
    return password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
}

// Password verification
function verifyPassword($password, $hash) {
    return password_verify($password, $hash);
}

// Token generation
function generateSecureToken($length = 32) {
    return bin2hex(random_bytes($length));
}

// JWT validation
function validateJWT($token) {
    global $jwt_secret;
    try {
        $decoded = JWT::decode($token, $jwt_secret, array('HS256'));
        return $decoded;
    } catch (Exception $e) {
        return false;
    }
}
?>
