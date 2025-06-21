<?php
header("Content-Type: application/json; charset=UTF-8");

// Include required files
require_once '../config.php';
require_once '../cors.php';

// Get request method and path
$method = $_SERVER['REQUEST_METHOD'];
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$path = trim(str_replace('/api/payments', '', $path), '/');

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

// Route handling
try {
    switch ($method) {
        case 'GET':
            if ($path) {
                // Get specific payment status
                $paymentId = intval($path);
                
                $stmt = $conn->prepare("SELECT p.*, u.name as user_name, u.email as user_email 
                                       FROM Payments p 
                                       JOIN Users u ON p.user_id = u.id 
                                       WHERE p.id = ? AND p.user_id = ?");
                $stmt->bind_param("ii", $paymentId, $userId);
                $stmt->execute();
                $result = $stmt->get_result();
                
                if ($result->num_rows === 0) {
                    throw new Exception("Payment not found or not authorized");
                }
                
                $payment = $result->fetch_assoc();
                echo json_encode([
                    "success" => true,
                    "payment" => $payment
                ]);
            } else {
                // Get all payments for user
                $page = isset($_GET['page']) ? max(1, intval($_GET['page'])) : 1;
                $limit = isset($_GET['limit']) ? min(100, max(1, intval($_GET['limit']))) : 10;
                $status = isset($_GET['status']) ? trim($_GET['status']) : '';
                
                $where = ["p.user_id = ?"];
                $params = [$userId];
                $types = "i";
                
                if ($status) {
                    $where[] = "p.status = ?";
                    $params[] = $status;
                    $types .= "s";
                }
                
                $whereClause = 'WHERE ' . implode(' AND ', $where);
                
                // Get total count
                $countSql = "SELECT COUNT(*) as total FROM Payments p $whereClause";
                $countStmt = $conn->prepare($countSql);
                $countStmt->bind_param($types, ...$params);
                $countStmt->execute();
                $totalResult = $countStmt->get_result();
                $total = $totalResult->fetch_assoc()['total'];
                
                // Calculate pagination
                $offset = ($page - 1) * $limit;
                $totalPages = ceil($total / $limit);
                
                // Get payments with pagination
                $sql = "SELECT p.*, u.name as user_name, u.email as user_email 
                        FROM Payments p 
                        JOIN Users u ON p.user_id = u.id 
                        $whereClause 
                        ORDER BY p.created_at DESC 
                        LIMIT ? OFFSET ?";
                $stmt = $conn->prepare($sql);
                
                $params[] = $limit;
                $params[] = $offset;
                $types .= "ii";
                $stmt->bind_param($types, ...$params);
                
                $stmt->execute();
                $result = $stmt->get_result();
                $payments = [];
                while ($row = $result->fetch_assoc()) {
                    $payments[] = $row;
                }
                
                echo json_encode([
                    "success" => true,
                    "data" => $payments,
                    "pagination" => [
                        "current_page" => $page,
                        "per_page" => $limit,
                        "total" => $total,
                        "total_pages" => $totalPages,
                        "has_next" => $page < $totalPages,
                        "has_prev" => $page > 1
                    ]
                ]);
            }
            break;

        case 'POST':
            // Create new payment
            if (!isset($input['amount']) || !isset($input['payment_method'])) {
                throw new Exception("Amount and payment method are required");
            }
            
            $amount = floatval($input['amount']);
            $paymentMethod = validateInput($input['payment_method']);
            $appointmentId = isset($input['appointment_id']) ? intval($input['appointment_id']) : null;
            $description = isset($input['description']) ? validateInput($input['description']) : '';
            $status = 'pending';
            
            // Validate amount
            if ($amount <= 0) {
                throw new Exception("Amount must be greater than 0");
            }
            
            // Validate payment method
            $allowedMethods = ['credit_card', 'debit_card', 'cash', 'bank_transfer'];
            if (!in_array($paymentMethod, $allowedMethods)) {
                throw new Exception("Invalid payment method");
            }
            
            // Check if appointment exists (if appointment_id provided)
            if ($appointmentId) {
                $appointmentStmt = $conn->prepare("SELECT id FROM Appointments WHERE id = ? AND user_id = ?");
                $appointmentStmt->bind_param("ii", $appointmentId, $userId);
                $appointmentStmt->execute();
                $appointmentResult = $appointmentStmt->get_result();
                
                if ($appointmentResult->num_rows === 0) {
                    throw new Exception("Appointment not found or not authorized");
                }
            }
            
            // Insert payment
            $stmt = $conn->prepare("INSERT INTO Payments (user_id, appointment_id, amount, payment_method, description, status, created_at) VALUES (?, ?, ?, ?, ?, ?, NOW())");
            $stmt->bind_param("iidsss", $userId, $appointmentId, $amount, $paymentMethod, $description, $status);
            
            if (!$stmt->execute()) {
                throw new Exception("Error creating payment: " . $stmt->error);
            }
            
            $paymentId = $conn->insert_id;
            
            echo json_encode([
                "success" => true,
                "message" => "Payment created successfully",
                "payment_id" => $paymentId,
                "payment" => [
                    "id" => $paymentId,
                    "user_id" => $userId,
                    "appointment_id" => $appointmentId,
                    "amount" => $amount,
                    "payment_method" => $paymentMethod,
                    "description" => $description,
                    "status" => $status
                ]
            ]);
            break;

        case 'PUT':
            // Update payment status (for admin/doctor)
            if ($userType !== 'admin' && $userType !== 'doctor') {
                throw new Exception("Only admins and doctors can update payment status");
            }
            
            if (!isset($input['payment_id']) || !isset($input['status'])) {
                throw new Exception("Payment ID and status are required");
            }
            
            $paymentId = intval($input['payment_id']);
            $status = validateInput($input['status']);
            
            // Validate status
            $allowedStatuses = ['pending', 'completed', 'failed', 'cancelled'];
            if (!in_array($status, $allowedStatuses)) {
                throw new Exception("Invalid status");
            }
            
            // Check if payment exists
            $checkStmt = $conn->prepare("SELECT id FROM Payments WHERE id = ?");
            $checkStmt->bind_param("i", $paymentId);
            $checkStmt->execute();
            $checkStmt->store_result();
            
            if ($checkStmt->num_rows === 0) {
                throw new Exception("Payment not found");
            }
            
            // Update payment status
            $stmt = $conn->prepare("UPDATE Payments SET status = ?, updated_at = NOW() WHERE id = ?");
            $stmt->bind_param("si", $status, $paymentId);
            
            if (!$stmt->execute()) {
                throw new Exception("Error updating payment: " . $stmt->error);
            }
            
            echo json_encode([
                "success" => true,
                "message" => "Payment status updated successfully"
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
}

// Close database connection
$conn->close();
?> 