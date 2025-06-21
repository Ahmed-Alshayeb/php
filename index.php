<?php
header("Content-Type: application/json; charset=UTF-8");

// Include required files
require_once 'config.php';
require_once 'cors.php';
require_once 'logger.php';
require_once 'rate_limit.php';

// Initialize logger
$logger = new Logger();

// Get request method and path
$method = $_SERVER['REQUEST_METHOD'];
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$path = trim(str_replace('/api', '', $path), '/');

// Parse request body
$input = json_decode(file_get_contents('php://input'), true);

// JWT Authentication
$headers = getallheaders();
if (!isset($headers['Authorization'])) {
    http_response_code(401);
    echo json_encode(["error" => "Authorization header is missing"]);
    $logger->warning("Missing Authorization header");
    exit;
}

$authHeader = $headers['Authorization'];
if (!preg_match('/Bearer\s(\S+)/', $authHeader, $matches)) {
    http_response_code(401);
    echo json_encode(["error" => "Invalid Authorization format"]);
    $logger->warning("Invalid Authorization format");
    exit;
}

$jwt = $matches[1];

// Validate JWT token
$tokenParts = explode('.', $jwt);
if (count($tokenParts) !== 3) {
    http_response_code(401);
    echo json_encode(["error" => "Invalid token format"]);
    $logger->error("Invalid token format");
    exit;
}

$payload = json_decode(base64_decode(str_replace(['-', '_'], ['+', '/'], $tokenParts[1])), true);

if (!$payload || !isset($payload['exp']) || $payload['exp'] < time()) {
    http_response_code(401);
    echo json_encode(["error" => "Token expired or invalid"]);
    $logger->error("Token expired or invalid");
    exit;
}

// Helper function to check if email exists
function emailExists($conn, $email, $excludeId = null) {
    $sql = "SELECT id FROM users WHERE email = ?";
    $params = [$email];
    $types = "s";
    
    if ($excludeId) {
        $sql .= " AND id != ?";
        $params[] = $excludeId;
        $types .= "i";
    }
    
    $stmt = $conn->prepare($sql);
    $stmt->bind_param($types, ...$params);
    $stmt->execute();
    $stmt->store_result();
    return $stmt->num_rows > 0;
}

// Helper function to build WHERE clause
function buildWhereClause($search, $filters) {
    $where = [];
    $params = [];
    $types = "";
    
    if ($search) {
        $where[] = "(name LIKE ? OR email LIKE ?)";
        $searchTerm = "%$search%";
        $params[] = $searchTerm;
        $params[] = $searchTerm;
        $types .= "ss";
    }
    
    if (isset($filters['status'])) {
        $where[] = "status = ?";
        $params[] = $filters['status'];
        $types .= "s";
    }
    
    if (isset($filters['created_after'])) {
        $where[] = "created_at >= ?";
        $params[] = $filters['created_after'];
        $types .= "s";
    }
    
    return [
        'where' => $where,
        'params' => $params,
        'types' => $types
    ];
}

// Route handling
try {
    // Split path for routing
    $path_parts = explode('/', $path);
    $main_route = $path_parts[0];

    switch ($main_route) {
        case 'users':
            switch ($method) {
                case 'GET':
                    // Get query parameters
                    $page = isset($_GET['page']) ? max(1, intval($_GET['page'])) : 1;
                    $limit = isset($_GET['limit']) ? min(100, max(1, intval($_GET['limit']))) : 10;
                    $search = isset($_GET['search']) ? trim($_GET['search']) : '';
                    $sort = isset($_GET['sort']) ? $_GET['sort'] : 'id';
                    $order = isset($_GET['order']) ? strtoupper($_GET['order']) : 'ASC';
                    $filters = $_GET;
                    
                    // Validate sort field
                    $allowedSortFields = ['id', 'name', 'email', 'created_at'];
                    if (!in_array($sort, $allowedSortFields)) {
                        $sort = 'id';
                    }
                    
                    // Validate order
                    if (!in_array($order, ['ASC', 'DESC'])) {
                        $order = 'ASC';
                    }
                    
                    // Build WHERE clause
                    $whereData = buildWhereClause($search, $filters);
                    $whereClause = !empty($whereData['where']) ? 'WHERE ' . implode(' AND ', $whereData['where']) : '';
                    
                    // Get total count
                    $countSql = "SELECT COUNT(*) as total FROM users $whereClause";
                    $countStmt = $conn->prepare($countSql);
                    if (!empty($whereData['params'])) {
                        $countStmt->bind_param($whereData['types'], ...$whereData['params']);
                    }
                    $countStmt->execute();
                    $totalResult = $countStmt->get_result();
                    $total = $totalResult->fetch_assoc()['total'];
                    
                    // Calculate pagination
                    $offset = ($page - 1) * $limit;
                    $totalPages = ceil($total / $limit);
                    
                    // Get users with pagination
                    $sql = "SELECT * FROM users $whereClause ORDER BY $sort $order LIMIT ? OFFSET ?";
                    $stmt = $conn->prepare($sql);
                    
                    if (!empty($whereData['params'])) {
                        $params = array_merge($whereData['params'], [$limit, $offset]);
                        $types = $whereData['types'] . "ii";
                        $stmt->bind_param($types, ...$params);
                    } else {
                        $stmt->bind_param("ii", $limit, $offset);
                    }
                    
                    $stmt->execute();
                    $result = $stmt->get_result();
                    $users = [];
                    while ($row = $result->fetch_assoc()) {
                        $users[] = $row;
                    }
                    
                    echo json_encode([
                        "success" => true,
                        "data" => $users,
                        "pagination" => [
                            "current_page" => $page,
                            "per_page" => $limit,
                            "total" => $total,
                            "total_pages" => $totalPages,
                            "has_next" => $page < $totalPages,
                            "has_prev" => $page > 1
                        ],
                        "filters" => [
                            "search" => $search,
                            "sort" => $sort,
                            "order" => $order
                        ]
                    ]);
                    $logger->info("Retrieved " . count($users) . " users (page $page)");
                    break;

                case 'POST':
                    // Create new user
                    if (!isset($input['name']) || !isset($input['email'])) {
                        throw new Exception("Name and email are required");
                    }
                    $name = validateInput($input['name']);
                    $email = validateInput($input['email']);
                    if (!validateEmail($email)) {
                        throw new Exception("Invalid email format");
                    }
                    
                    // Check for duplicate email
                    if (emailExists($conn, $email)) {
                        throw new Exception("Email already exists");
                    }
                    
                    $stmt = $conn->prepare("INSERT INTO users (name, email, created_at) VALUES (?, ?, NOW())");
                    $stmt->bind_param("ss", $name, $email);
                    if (!$stmt->execute()) {
                        throw new Exception("Error creating user: " . $stmt->error);
                    }
                    
                    $userId = $conn->insert_id;
                    echo json_encode([
                        "success" => true,
                        "message" => "User created successfully",
                        "user" => [
                            "id" => $userId,
                            "name" => $name,
                            "email" => $email
                        ]
                    ]);
                    $logger->info("User created: $email (ID: $userId)");
                    break;

                case 'PUT':
                    // Update user
                    if (!isset($input['id'], $input['name'], $input['email'])) {
                        throw new Exception("Missing required fields");
                    }
                    $id = intval($input['id']);
                    $name = validateInput($input['name']);
                    $email = validateInput($input['email']);
                    if (!validateEmail($email)) {
                        throw new Exception("Invalid email format");
                    }
                    
                    // Check for duplicate email (excluding current user)
                    if (emailExists($conn, $email, $id)) {
                        throw new Exception("Email already exists");
                    }
                    
                    $stmt = $conn->prepare("UPDATE users SET name = ?, email = ?, updated_at = NOW() WHERE id = ?");
                    $stmt->bind_param("ssi", $name, $email, $id);
                    if (!$stmt->execute()) {
                        throw new Exception("Error updating user: " . $stmt->error);
                    }
                    
                    if ($stmt->affected_rows === 0) {
                        throw new Exception("User not found");
                    }
                    
                    echo json_encode([
                        "success" => true,
                        "message" => "User updated successfully",
                        "user_id" => $id
                    ]);
                    $logger->info("User updated: ID $id");
                    break;

                case 'DELETE':
                    // Delete user
                    if (!isset($input['id'])) {
                        throw new Exception("User ID is required");
                    }
                    $id = intval($input['id']);
                    
                    // Check if user exists
                    $checkStmt = $conn->prepare("SELECT id FROM users WHERE id = ?");
                    $checkStmt->bind_param("i", $id);
                    $checkStmt->execute();
                    $checkStmt->store_result();
                    
                    if ($checkStmt->num_rows === 0) {
                        throw new Exception("User not found");
                    }
                    
                    $stmt = $conn->prepare("DELETE FROM users WHERE id = ?");
                    $stmt->bind_param("i", $id);
                    if (!$stmt->execute()) {
                        throw new Exception("Error deleting user: " . $stmt->error);
                    }
                    
                    echo json_encode([
                        "success" => true,
                        "message" => "User deleted successfully",
                        "user_id" => $id
                    ]);
                    $logger->info("User deleted: ID $id");
                    break;

                default:
                    throw new Exception("Method not allowed");
            }
            break;

        case 'hospitals':
            require_once 'hospitals/index.php';
            break;

        case 'pharmacies':
            require_once 'pharmacies/index.php';
            break;

        case 'ai':
            if (isset($path_parts[1]) && $path_parts[1] === 'predict') {
                require_once 'ai/predict.php';
            } else {
                http_response_code(404);
                echo json_encode(["error" => "AI endpoint not found"]);
            }
            break;

        case 'ambulances':
            require_once 'ambulances/index.php';
            break;
            
        case 'ambulance-requests':
            require_once 'ambulance-requests/index.php';
            break;

        case 'monitors':
            require_once 'monitors/index.php';
            break;

        default:
            http_response_code(404);
            echo json_encode(["error" => "Endpoint not found"]);
            $logger->warning("Endpoint not found: $path");
            break;
    }
} catch (Exception $e) {
    http_response_code(400);
    echo json_encode([
        "error" => $e->getMessage()
    ]);
    $logger->error($e->getMessage());
}

// Close database connection
$conn->close();
?> 