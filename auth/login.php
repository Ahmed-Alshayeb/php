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
    if (!isset($input['email']) || !isset($input['password'])) {
        throw new Exception("Email and password are required");
    }
    
    $email = validateInput($input['email']);
    $password = $input['password'];
    
    // Validate email format
    if (!validateEmail($email)) {
        throw new Exception("Invalid email format");
    }
    
    // Check if user exists in Users table
    $stmt = $conn->prepare("SELECT id, name, email, password, type FROM Users WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($result->num_rows === 0) {
        // Check if it's a doctor login
        $stmt = $conn->prepare("SELECT id, name, email, password, specialization, hospital_id FROM Doctors WHERE email = ?");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($result->num_rows === 0) {
            throw new Exception("Invalid email or password");
        }
        
        $user = $result->fetch_assoc();
        $user['type'] = 'doctor';
        
        // Verify password
        if (!verifyPassword($password, $user['password'])) {
            throw new Exception("Invalid email or password");
        }
        
        // Get hospital info if available
        if ($user['hospital_id']) {
            $stmt = $conn->prepare("SELECT name as hospital_name FROM Hospitals WHERE id = ?");
            $stmt->bind_param("i", $user['hospital_id']);
            $stmt->execute();
            $hospitalResult = $stmt->get_result();
            if ($hospitalResult->num_rows > 0) {
                $hospital = $hospitalResult->fetch_assoc();
                $user['hospital_name'] = $hospital['hospital_name'];
            }
        }
    } else {
        $user = $result->fetch_assoc();
        
        // Verify password
        if (!verifyPassword($password, $user['password'])) {
            throw new Exception("Invalid email or password");
        }
    }
    
    // Generate JWT token
    $payload = [
        'user_id' => $user['id'],
        'email' => $user['email'],
        'user_type' => $user['type'],
        'iat' => time(),
        'exp' => time() + $jwt_expiry
    ];
    
    $token = generateJWT($payload);
    
    // Generate refresh token
    $refreshToken = generateSecureToken(64);
    
    // Store refresh token in database (for users, not doctors)
    if ($user['type'] !== 'doctor') {
        $stmt = $conn->prepare("UPDATE Users SET refresh_token = ?, last_login = NOW() WHERE id = ?");
        $stmt->bind_param("si", $refreshToken, $user['id']);
        $stmt->execute();
    }
    
    // Remove sensitive data
    unset($user['password']);
    
    echo json_encode([
        "success" => true,
        "message" => "Login successful",
        "access_token" => $token,
        "refresh_token" => $refreshToken,
        "expires_in" => $jwt_expiry,
        "user" => $user
    ]);
    
    $logger->info("User logged in: {$user['email']} (ID: {$user['id']}, Type: {$user['type']})");
    
} catch (Exception $e) {
    http_response_code(400);
    echo json_encode([
        "error" => $e->getMessage()
    ]);
    $logger->error("Login failed: " . $e->getMessage());
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