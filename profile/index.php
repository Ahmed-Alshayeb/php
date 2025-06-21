<?php
header("Content-Type: application/json; charset=UTF-8");

// Include required files
require_once '../config.php';
require_once '../cors.php';

// Get request method and path
$method = $_SERVER['REQUEST_METHOD'];
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$path = trim(str_replace('/api/profile', '', $path), '/');

// Parse request body
$input = json_decode(file_get_contents('php://input'), true);

// JWT Authentication
$headers = getallheaders();
if (!isset($headers['Authorization'])) {
    http_response_code(401);
    echo json_encode(["error" => "Authorization header is missing"]);
    exit;
}

$authHeader = $headers['Authorization'];
if (!preg_match('/Bearer\s(\S+)/', $authHeader, $matches)) {
    http_response_code(401);
    echo json_encode(["error" => "Invalid Authorization format"]);
    exit;
}

$jwt = $matches[1];

// Validate JWT token
$tokenParts = explode('.', $jwt);
if (count($tokenParts) !== 3) {
    http_response_code(401);
    echo json_encode(["error" => "Invalid token format"]);
    exit;
}

$payload = json_decode(base64_decode(str_replace(['-', '_'], ['+', '/'], $tokenParts[1])), true);

if (!$payload || !isset($payload['exp']) || $payload['exp'] < time()) {
    http_response_code(401);
    echo json_encode(["error" => "Token expired or invalid"]);
    exit;
}

$userId = $payload['user_id'] ?? null;
$userType = $payload['user_type'] ?? null;

if (!$userId || !$userType) {
    http_response_code(401);
    echo json_encode(["error" => "Invalid token payload"]);
    exit;
}

// Helper function to validate input
function validateInput($data) {
    $data = trim($data);
    $data = stripslashes($data);
    $data = htmlspecialchars($data);
    return $data;
}

// Helper function to validate email
function validateEmail($email) {
    return filter_var($email, FILTER_VALIDATE_EMAIL);
}

// Route handling
try {
    switch ($method) {
        case 'GET':
            // Get user profile
            if ($userType === 'doctor') {
                // Get doctor profile with additional details
                $stmt = $conn->prepare("SELECT u.*, d.specialization, d.license_number, d.experience_years, 
                                              d.hospital_id, d.address, d.phone, d.bio, d.consultation_fee,
                                              h.name as hospital_name
                                       FROM Users u 
                                       LEFT JOIN Doctors d ON u.id = d.user_id 
                                       LEFT JOIN Hospitals h ON d.hospital_id = h.id 
                                       WHERE u.id = ?");
                $stmt->bind_param("i", $userId);
            } else {
                // Get patient profile
                $stmt = $conn->prepare("SELECT u.*, p.date_of_birth, p.gender, p.phone, p.address, p.emergency_contact
                                       FROM Users u 
                                       LEFT JOIN Patients p ON u.id = p.user_id 
                                       WHERE u.id = ?");
                $stmt->bind_param("i", $userId);
            }
            
            $stmt->execute();
            $result = $stmt->get_result();
            
            if ($result->num_rows === 0) {
                throw new Exception("User not found");
            }
            
            $profile = $result->fetch_assoc();
            
            // Remove sensitive information
            unset($profile['password']);
            
            echo json_encode([
                "success" => true,
                "profile" => $profile
            ]);
            break;

        case 'PUT':
            // Update user profile
            if (!isset($input['name']) || !isset($input['email'])) {
                throw new Exception("Name and email are required");
            }
            
            $name = validateInput($input['name']);
            $email = validateInput($input['email']);
            
            if (!validateEmail($email)) {
                throw new Exception("Invalid email format");
            }
            
            // Check if email already exists (excluding current user)
            $emailStmt = $conn->prepare("SELECT id FROM Users WHERE email = ? AND id != ?");
            $emailStmt->bind_param("si", $email, $userId);
            $emailStmt->execute();
            $emailStmt->store_result();
            
            if ($emailStmt->num_rows > 0) {
                throw new Exception("Email already exists");
            }
            
            // Update user basic info
            $stmt = $conn->prepare("UPDATE Users SET name = ?, email = ?, updated_at = NOW() WHERE id = ?");
            $stmt->bind_param("ssi", $name, $email, $userId);
            
            if (!$stmt->execute()) {
                throw new Exception("Error updating user: " . $stmt->error);
            }
            
            // Update specific profile based on user type
            if ($userType === 'doctor') {
                // Update doctor specific fields
                $specialization = isset($input['specialization']) ? validateInput($input['specialization']) : '';
                $licenseNumber = isset($input['license_number']) ? validateInput($input['license_number']) : '';
                $experienceYears = isset($input['experience_years']) ? intval($input['experience_years']) : 0;
                $hospitalId = isset($input['hospital_id']) ? intval($input['hospital_id']) : null;
                $address = isset($input['address']) ? validateInput($input['address']) : '';
                $phone = isset($input['phone']) ? validateInput($input['phone']) : '';
                $bio = isset($input['bio']) ? validateInput($input['bio']) : '';
                $consultationFee = isset($input['consultation_fee']) ? floatval($input['consultation_fee']) : 0;
                
                // Check if doctor record exists
                $checkStmt = $conn->prepare("SELECT id FROM Doctors WHERE user_id = ?");
                $checkStmt->bind_param("i", $userId);
                $checkStmt->execute();
                $checkResult = $checkStmt->get_result();
                
                if ($checkResult->num_rows > 0) {
                    // Update existing doctor record
                    $updateStmt = $conn->prepare("UPDATE Doctors SET 
                                                 specialization = ?, license_number = ?, experience_years = ?, 
                                                 hospital_id = ?, address = ?, phone = ?, bio = ?, consultation_fee = ?, 
                                                 updated_at = NOW() 
                                                 WHERE user_id = ?");
                    $updateStmt->bind_param("ssiissdsi", $specialization, $licenseNumber, $experienceYears, 
                                           $hospitalId, $address, $phone, $bio, $consultationFee, $userId);
                } else {
                    // Create new doctor record
                    $insertStmt = $conn->prepare("INSERT INTO Doctors (user_id, specialization, license_number, 
                                                 experience_years, hospital_id, address, phone, bio, consultation_fee, created_at) 
                                                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())");
                    $insertStmt->bind_param("issiissds", $userId, $specialization, $licenseNumber, 
                                           $experienceYears, $hospitalId, $address, $phone, $bio, $consultationFee);
                }
                
                if (!$updateStmt->execute() && !$insertStmt->execute()) {
                    throw new Exception("Error updating doctor profile");
                }
                
            } else {
                // Update patient specific fields
                $dateOfBirth = isset($input['date_of_birth']) ? validateInput($input['date_of_birth']) : null;
                $gender = isset($input['gender']) ? validateInput($input['gender']) : '';
                $phone = isset($input['phone']) ? validateInput($input['phone']) : '';
                $address = isset($input['address']) ? validateInput($input['address']) : '';
                $emergencyContact = isset($input['emergency_contact']) ? validateInput($input['emergency_contact']) : '';
                
                // Check if patient record exists
                $checkStmt = $conn->prepare("SELECT id FROM Patients WHERE user_id = ?");
                $checkStmt->bind_param("i", $userId);
                $checkStmt->execute();
                $checkResult = $checkStmt->get_result();
                
                if ($checkResult->num_rows > 0) {
                    // Update existing patient record
                    $updateStmt = $conn->prepare("UPDATE Patients SET 
                                                 date_of_birth = ?, gender = ?, phone = ?, address = ?, 
                                                 emergency_contact = ?, updated_at = NOW() 
                                                 WHERE user_id = ?");
                    $updateStmt->bind_param("sssssi", $dateOfBirth, $gender, $phone, $address, $emergencyContact, $userId);
                } else {
                    // Create new patient record
                    $insertStmt = $conn->prepare("INSERT INTO Patients (user_id, date_of_birth, gender, phone, 
                                                 address, emergency_contact, created_at) 
                                                 VALUES (?, ?, ?, ?, ?, ?, NOW())");
                    $insertStmt->bind_param("isssss", $userId, $dateOfBirth, $gender, $phone, $address, $emergencyContact);
                }
                
                if (!$updateStmt->execute() && !$insertStmt->execute()) {
                    throw new Exception("Error updating patient profile");
                }
            }
            
            echo json_encode([
                "success" => true,
                "message" => "Profile updated successfully"
            ]);
            break;

        case 'POST':
            if ($path === 'change-password') {
                // Change password
                if (!isset($input['current_password']) || !isset($input['new_password'])) {
                    throw new Exception("Current password and new password are required");
                }
                
                $currentPassword = $input['current_password'];
                $newPassword = $input['new_password'];
                
                // Validate new password
                if (strlen($newPassword) < 6) {
                    throw new Exception("New password must be at least 6 characters long");
                }
                
                // Get current password hash
                $stmt = $conn->prepare("SELECT password FROM Users WHERE id = ?");
                $stmt->bind_param("i", $userId);
                $stmt->execute();
                $result = $stmt->get_result();
                
                if ($result->num_rows === 0) {
                    throw new Exception("User not found");
                }
                
                $user = $result->fetch_assoc();
                
                // Verify current password
                if (!password_verify($currentPassword, $user['password'])) {
                    throw new Exception("Current password is incorrect");
                }
                
                // Hash new password
                $newPasswordHash = password_hash($newPassword, PASSWORD_DEFAULT);
                
                // Update password
                $updateStmt = $conn->prepare("UPDATE Users SET password = ?, updated_at = NOW() WHERE id = ?");
                $updateStmt->bind_param("si", $newPasswordHash, $userId);
                
                if (!$updateStmt->execute()) {
                    throw new Exception("Error updating password");
                }
                
                echo json_encode([
                    "success" => true,
                    "message" => "Password changed successfully"
                ]);
            } else {
                throw new Exception("Invalid endpoint");
            }
            break;

        default:
            throw new Exception("Method not allowed");
    }
} catch (Exception $e) {
    http_response_code(400);
    echo json_encode([
        "error" => $e->getMessage()
    ]);
}

// Close database connection
$conn->close();
?> 