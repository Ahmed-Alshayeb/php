<?php
header("Content-Type: application/json; charset=UTF-8");

// Include required files
require_once '../config.php';
require_once '../cors.php';
require_once '../logger.php';
require_once '../rate_limit.php';

// Initialize logger
$logger = new Logger();

// Only allow POST method
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(["error" => "Method not allowed"]);
    exit;
}

// Parse request body
$input = json_decode(file_get_contents('php://input'), true);

try {
    // Validate required fields
    if (!isset($input['name']) || !isset($input['email']) || !isset($input['password']) || !isset($input['type'])) {
        throw new Exception("Name, email, password, and type are required");
    }
    
    $name = validateInput($input['name']);
    $email = validateInput($input['email']);
    $password = $input['password'];
    $userType = validateInput($input['type']);
    
    // Validate email format
    if (!validateEmail($email)) {
        throw new Exception("Invalid email format");
    }
    
    // Validate password strength
    if (strlen($password) < 6) {
        throw new Exception("Password must be at least 6 characters long");
    }
    
    // Validate user type
    $allowedUserTypes = ['patient', 'admin'];
    if (!in_array($userType, $allowedUserTypes)) {
        throw new Exception("Invalid user type. Only 'patient' and 'admin' are allowed for registration");
    }
    
    // Check if email already exists in Users table
    $stmt = $conn->prepare("SELECT id FROM Users WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $stmt->store_result();
    
    if ($stmt->num_rows > 0) {
        throw new Exception("Email already exists");
    }
    
    // Check if email exists in Doctors table
    $stmt = $conn->prepare("SELECT id FROM Doctors WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $stmt->store_result();
    
    if ($stmt->num_rows > 0) {
        throw new Exception("Email already exists");
    }
    
    // Hash password
    $hashedPassword = hashPassword($password);
    
    // Generate refresh token
    $refreshToken = generateSecureToken(64);
    
    // Insert new user
    $stmt = $conn->prepare("INSERT INTO Users (name, email, password, type, refresh_token, created_at) VALUES (?, ?, ?, ?, ?, NOW())");
    $stmt->bind_param("sssss", $name, $email, $hashedPassword, $userType, $refreshToken);
    
    if (!$stmt->execute()) {
        throw new Exception("Error creating user: " . $stmt->error);
    }
    
    $userId = $conn->insert_id;
    
    // Generate JWT token
    $payload = [
        'user_id' => $userId,
        'email' => $email,
        'user_type' => $userType,
        'iat' => time(),
        'exp' => time() + $jwt_expiry
    ];
    
    $token = generateJWT($payload);
    
    echo json_encode([
        "success" => true,
        "message" => "User registered successfully",
        "access_token" => $token,
        "refresh_token" => $refreshToken,
        "expires_in" => $jwt_expiry,
        "user" => [
            "id" => $userId,
            "name" => $name,
            "email" => $email,
            "type" => $userType
        ]
    ]);
    
    $logger->info("User registered: $email (ID: $userId, Type: $userType)");
    
} catch (Exception $e) {
    http_response_code(400);
    echo json_encode([
        "error" => $e->getMessage()
    ]);
    $logger->error("Registration failed: " . $e->getMessage());
}

// Close database connection
$conn->close();

// JWT generation function
function generateJWT($payload) {
    global $jwt_secret;
    
    $header = json_encode(['typ' => 'JWT', 'alg' => 'HS256']);
    $payload = json_encode($payload);
    
    $base64Header = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($header));
    $base64Payload = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($payload));
    
    $signature = hash_hmac('sha256', $base64Header . "." . $base64Payload, $jwt_secret, true);
    $base64Signature = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($signature));
    
    return $base64Header . "." . $base64Payload . "." . $base64Signature;
}
?> 