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

// Only allow GET method
if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    http_response_code(405);
    echo json_encode(["error" => "Method not allowed"]);
    exit;
}

try {
    // Get query parameters
    $page = isset($_GET['page']) ? max(1, intval($_GET['page'])) : 1;
    $limit = isset($_GET['limit']) ? min(100, max(1, intval($_GET['limit']))) : 10;
    $query = isset($_GET['q']) ? trim($_GET['q']) : '';
    $specialization = isset($_GET['specialization']) ? trim($_GET['specialization']) : '';
    $hospital_id = isset($_GET['hospital_id']) ? intval($_GET['hospital_id']) : 0;
    $sortBy = isset($_GET['sort_by']) ? trim($_GET['sort_by']) : 'name';
    $sortOrder = isset($_GET['sort_order']) ? strtoupper(trim($_GET['sort_order'])) : 'ASC';
    
    // Validate sort parameters
    $allowedSortFields = ['name', 'specialization', 'created_at'];
    if (!in_array($sortBy, $allowedSortFields)) {
        $sortBy = 'name';
    }
    
    if (!in_array($sortOrder, ['ASC', 'DESC'])) {
        $sortOrder = 'ASC';
    }
    
    // Build WHERE clause
    $where = [];
    $params = [];
    $types = "";
    
    if ($query) {
        $where[] = "(d.name LIKE ? OR d.specialization LIKE ?)";
        $searchTerm = "%$query%";
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
    $sql = "SELECT d.id, d.name, d.email, d.phone, d.specialization, 
                   d.hospital_id, d.available_times, d.created_at,
                   h.name as hospital_name, h.address as hospital_address, h.phone as hospital_phone
            FROM Doctors d
            LEFT JOIN Hospitals h ON d.hospital_id = h.id
            $whereClause
            ORDER BY d.$sortBy $sortOrder, d.name ASC
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
    
    // Get available specializations for filter
    $specSql = "SELECT DISTINCT specialization FROM Doctors ORDER BY specialization";
    $specStmt = $conn->prepare($specSql);
    $specStmt->execute();
    $specResult = $specStmt->get_result();
    $specializations = [];
    while ($row = $specResult->fetch_assoc()) {
        $specializations[] = $row['specialization'];
    }
    
    // Get available hospitals for filter
    $hospSql = "SELECT id, name FROM Hospitals ORDER BY name";
    $hospStmt = $conn->prepare($hospSql);
    $hospStmt->execute();
    $hospResult = $hospStmt->get_result();
    $hospitals = [];
    while ($row = $hospResult->fetch_assoc()) {
        $hospitals[] = $row;
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
        ],
        "filters" => [
            "query" => $query,
            "specialization" => $specialization,
            "hospital_id" => $hospital_id,
            "sort_by" => $sortBy,
            "sort_order" => $sortOrder
        ],
        "available_filters" => [
            "specializations" => $specializations,
            "hospitals" => $hospitals
        ]
    ]);
    
    $logger->info("Doctor search completed: $total results found");
    
} catch (Exception $e) {
    http_response_code(400);
    echo json_encode([
        "error" => $e->getMessage()
    ]);
    $logger->error("Doctor search error: " . $e->getMessage());
}

// Close database connection
$conn->close();
?> 