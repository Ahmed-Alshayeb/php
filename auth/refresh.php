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
    if (!isset($input['refresh_token'])) {
        throw new Exception("Refresh token is required");
    }
    
    $refreshToken = $input['refresh_token'];
    
    // Find user by refresh token
    $stmt = $conn->prepare("SELECT id, name, email, user_type, status FROM Users WHERE refresh_token = ? AND status = 'active'");
    $stmt->bind_param("s", $refreshToken);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($result->num_rows === 0) {
        throw new Exception("Invalid refresh token");
    }
    
    $user = $result->fetch_assoc();
    
    // Generate new JWT token
    $payload = [
        'user_id' => $user['id'],
        'email' => $user['email'],
        'user_type' => $user['user_type'],
        'iat' => time(),
        'exp' => time() + $jwt_expiry
    ];
    
    $newToken = generateJWT($payload);
    
    // Generate new refresh token
    $newRefreshToken = generateSecureToken(64);
    
    // Update refresh token in database
    $stmt = $conn->prepare("UPDATE Users SET refresh_token = ?, updated_at = NOW() WHERE id = ?");
    $stmt->bind_param("si", $newRefreshToken, $user['id']);
    $stmt->execute();
    
    echo json_encode([
        "success" => true,
        "message" => "Token refreshed successfully",
        "access_token" => $newToken,
        "refresh_token" => $newRefreshToken,
        "expires_in" => $jwt_expiry,
        "user" => $user
    ]);
    
    $logger->info("Token refreshed for user: {$user['email']} (ID: {$user['id']})");
    
} catch (Exception $e) {
    http_response_code(400);
    echo json_encode([
        "error" => $e->getMessage()
    ]);
    $logger->error("Token refresh failed: " . $e->getMessage());
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