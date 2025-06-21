<?php
header("Content-Type: application/json; charset=UTF-8");

// Include required files
require_once '../config.php';
require_once '../cors.php';
require_once '../logger.php';
require_once '../rate_limit.php';

// Initialize logger
$logger = new Logger();

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

// Get request method
$method = $_SERVER['REQUEST_METHOD'];
$input = json_decode(file_get_contents('php://input'), true);

try {
    switch ($method) {
        case 'GET':
            // Get query parameters
            $page = isset($_GET['page']) ? max(1, intval($_GET['page'])) : 1;
            $limit = isset($_GET['limit']) ? min(100, max(1, intval($_GET['limit']))) : 10;
            $search = isset($_GET['search']) ? trim($_GET['search']) : '';
            $specialization = isset($_GET['specialization']) ? trim($_GET['specialization']) : '';
            $hospital_id = isset($_GET['hospital_id']) ? intval($_GET['hospital_id']) : 0;
            
            // Build WHERE clause
            $where = [];
            $params = [];
            $types = "";
            
            if ($search) {
                $where[] = "(d.name LIKE ? OR d.specialization LIKE ?)";
                $searchTerm = "%$search%";
                $params[] = $searchTerm;
                $params[] = $searchTerm;
                $types .= "ss";
            }
            
            if ($specialization) {
                $where[] = "d.specialization = ?";
                $params[] = $specialization;
                $types .= "s";
            }
            
            if ($hospital_id > 0) {
                $where[] = "d.hospital_id = ?";
                $params[] = $hospital_id;
                $types .= "i";
            }
            
            $whereClause = !empty($where) ? 'WHERE ' . implode(' AND ', $where) : '';
            
            // Get total count
            $countSql = "SELECT COUNT(*) as total FROM Doctors d LEFT JOIN Hospitals h ON d.hospital_id = h.id $whereClause";
            $countStmt = $conn->prepare($countSql);
            if (!empty($params)) {
                $countStmt->bind_param($types, ...$params);
            }
            $countStmt->execute();
            $totalResult = $countStmt->get_result();
            $total = $totalResult->fetch_assoc()['total'];
            
            // Calculate pagination
            $offset = ($page - 1) * $limit;
            $totalPages = ceil($total / $limit);
            
            // Get doctors with pagination
            $sql = "SELECT d.*, h.name as hospital_name, h.address as hospital_address 
                    FROM Doctors d 
                    LEFT JOIN Hospitals h ON d.hospital_id = h.id 
                    $whereClause 
                    ORDER BY d.name ASC 
                    LIMIT ? OFFSET ?";
            
            $stmt = $conn->prepare($sql);
            
            if (!empty($params)) {
                $params[] = $limit;
                $params[] = $offset;
                $types .= "ii";
                $stmt->bind_param($types, ...$params);
            } else {
                $stmt->bind_param("ii", $limit, $offset);
            }
            
            $stmt->execute();
            $result = $stmt->get_result();
            $doctors = [];
            while ($row = $result->fetch_assoc()) {
                // Remove sensitive data
                unset($row['password']);
                $doctors[] = $row;
            }
            
            echo json_encode([
                "success" => true,
                "data" => $doctors,
                "pagination" => [
                    "current_page" => $page,
                    "per_page" => $limit,
                    "total" => $total,
                    "total_pages" => $totalPages,
                    "has_next" => $page < $totalPages,
                    "has_prev" => $page > 1
                ]
            ]);
            break;
            
        case 'POST':
            // Create new doctor (admin only)
            if ($payload['user_type'] !== 'admin') {
                throw new Exception("Only admins can create doctor accounts");
            }
            
            if (!isset($input['name']) || !isset($input['email']) || !isset($input['password']) || !isset($input['specialization'])) {
                throw new Exception("Name, email, password, and specialization are required");
            }
            
            $name = validateInput($input['name']);
            $email = validateInput($input['email']);
            $password = $input['password'];
            $specialization = validateInput($input['specialization']);
            $phone = isset($input['phone']) ? validateInput($input['phone']) : '';
            $hospital_id = isset($input['hospital_id']) ? intval($input['hospital_id']) : null;
            $available_times = isset($input['available_times']) ? json_encode($input['available_times']) : '';
            
            // Validate email format
            if (!validateEmail($email)) {
                throw new Exception("Invalid email format");
            }
            
            // Validate password strength
            if (strlen($password) < 6) {
                throw new Exception("Password must be at least 6 characters long");
            }
            
            // Check if email already exists
            $checkStmt = $conn->prepare("SELECT id FROM Doctors WHERE email = ?");
            $checkStmt->bind_param("s", $email);
            $checkStmt->execute();
            $checkStmt->store_result();
            
            if ($checkStmt->num_rows > 0) {
                throw new Exception("Email already exists");
            }
            
            // Check if email exists in Users table
            $checkUserStmt = $conn->prepare("SELECT id FROM Users WHERE email = ?");
            $checkUserStmt->bind_param("s", $email);
            $checkUserStmt->execute();
            $checkUserStmt->store_result();
            
            if ($checkUserStmt->num_rows > 0) {
                throw new Exception("Email already exists");
            }
            
            // Hash password
            $hashedPassword = hashPassword($password);
            
            // Insert doctor
            $stmt = $conn->prepare("INSERT INTO Doctors (name, email, password, phone, specialization, hospital_id, available_times, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, NOW())");
            $stmt->bind_param("sssssis", $name, $email, $hashedPassword, $phone, $specialization, $hospital_id, $available_times);
            
            if (!$stmt->execute()) {
                throw new Exception("Error creating doctor: " . $stmt->error);
            }
            
            $doctorId = $conn->insert_id;
            
            echo json_encode([
                "success" => true,
                "message" => "Doctor created successfully",
                "doctor_id" => $doctorId
            ]);
            break;
            
        default:
            throw new Exception("Method not allowed");
    }
    
} catch (Exception $e) {
    http_response_code(400);
    echo json_encode([
        "error" => $e->getMessage()
    ]);
    $logger->error("Doctors API error: " . $e->getMessage());
}

// Close database connection
$conn->close();
?> 