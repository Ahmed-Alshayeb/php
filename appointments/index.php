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

$userId = $payload['user_id'];
$userType = $payload['user_type'];

// Get request method
$method = $_SERVER['REQUEST_METHOD'];
$input = json_decode(file_get_contents('php://input'), true);

try {
    switch ($method) {
        case 'GET':
            // Get appointments based on user type
            $page = isset($_GET['page']) ? max(1, intval($_GET['page'])) : 1;
            $limit = isset($_GET['limit']) ? min(100, max(1, intval($_GET['limit']))) : 10;
            $status = isset($_GET['status']) ? trim($_GET['status']) : '';
            
            // Build WHERE clause based on user type
            $where = [];
            $params = [];
            $types = "";
            
            if ($userType === 'doctor') {
                $where[] = "a.doctor_id = ?";
                $params[] = $userId;
                $types .= "i";
            } else {
                $where[] = "a.user_id = ?";
                $params[] = $userId;
                $types .= "i";
            }
            
            if ($status) {
                $where[] = "a.status = ?";
                $params[] = $status;
                $types .= "s";
            }
            
            $whereClause = 'WHERE ' . implode(' AND ', $where);
            
            // Get total count
            $countSql = "SELECT COUNT(*) as total FROM Appointments a $whereClause";
            $countStmt = $conn->prepare($countSql);
            $countStmt->bind_param($types, ...$params);
            $countStmt->execute();
            $totalResult = $countStmt->get_result();
            $total = $totalResult->fetch_assoc()['total'];
            
            // Calculate pagination
            $offset = ($page - 1) * $limit;
            $totalPages = ceil($total / $limit);
            
            // Get appointments with pagination
            $sql = "SELECT a.*, 
                           u.name as patient_name, u.email as patient_email,
                           d.name as doctor_name, d.email as doctor_email, d.specialization,
                           l.name as lab_name, l.address as lab_address
                    FROM Appointments a
                    LEFT JOIN Users u ON a.user_id = u.id
                    LEFT JOIN Doctors d ON a.doctor_id = d.id
                    LEFT JOIN Labs l ON a.lab_id = l.id
                    $whereClause
                    ORDER BY a.date DESC
                    LIMIT ? OFFSET ?";
            
            $stmt = $conn->prepare($sql);
            $params[] = $limit;
            $params[] = $offset;
            $types .= "ii";
            $stmt->bind_param($types, ...$params);
            
            $stmt->execute();
            $result = $stmt->get_result();
            $appointments = [];
            while ($row = $result->fetch_assoc()) {
                $appointments[] = $row;
            }
            
            echo json_encode([
                "success" => true,
                "data" => $appointments,
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
            // Create new appointment
            if (!isset($input['date'])) {
                throw new Exception("Appointment date and time are required");
            }
            
            $date = validateInput($input['date']);
            $doctorId = isset($input['doctor_id']) ? intval($input['doctor_id']) : null;
            $labId = isset($input['lab_id']) ? intval($input['lab_id']) : null;
            $status = 'pending';
            
            // Validate that either doctor_id or lab_id is provided
            if (!$doctorId && !$labId) {
                throw new Exception("Either doctor_id or lab_id is required");
            }
            
            // Validate date format (expecting DATETIME format)
            if (!preg_match('/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/', $date)) {
                throw new Exception("Invalid date format. Use YYYY-MM-DD HH:MM:SS");
            }
            
            // Check if appointment date is in the future
            if (strtotime($date) <= time()) {
                throw new Exception("Appointment must be scheduled for a future date and time");
            }
            
            // Check if doctor exists (if doctor_id provided)
            if ($doctorId) {
                $doctorStmt = $conn->prepare("SELECT id FROM Doctors WHERE id = ?");
                $doctorStmt->bind_param("i", $doctorId);
                $doctorStmt->execute();
                $doctorResult = $doctorStmt->get_result();
                
                if ($doctorResult->num_rows === 0) {
                    throw new Exception("Doctor not found");
                }
            }
            
            // Check if lab exists (if lab_id provided)
            if ($labId) {
                $labStmt = $conn->prepare("SELECT id FROM Labs WHERE id = ?");
                $labStmt->bind_param("i", $labId);
                $labStmt->execute();
                $labResult = $labStmt->get_result();
                
                if ($labResult->num_rows === 0) {
                    throw new Exception("Lab not found");
                }
            }
            
            // Check if appointment slot is available
            $slotStmt = $conn->prepare("SELECT id FROM Appointments WHERE date = ? AND status IN ('pending', 'confirmed')");
            if ($doctorId) {
                $slotStmt = $conn->prepare("SELECT id FROM Appointments WHERE doctor_id = ? AND date = ? AND status IN ('pending', 'confirmed')");
                $slotStmt->bind_param("is", $doctorId, $date);
            } else {
                $slotStmt->bind_param("s", $date);
            }
            $slotStmt->execute();
            $slotStmt->store_result();
            
            if ($slotStmt->num_rows > 0) {
                throw new Exception("Appointment slot is not available");
            }
            
            // Insert appointment
            $stmt = $conn->prepare("INSERT INTO Appointments (user_id, doctor_id, lab_id, date, status, created_at) VALUES (?, ?, ?, ?, ?, NOW())");
            $stmt->bind_param("iiiss", $userId, $doctorId, $labId, $date, $status);
            
            if (!$stmt->execute()) {
                throw new Exception("Error creating appointment: " . $stmt->error);
            }
            
            $appointmentId = $conn->insert_id;
            
            echo json_encode([
                "success" => true,
                "message" => "Appointment created successfully",
                "appointment_id" => $appointmentId
            ]);
            break;
            
        case 'PUT':
            // Update appointment status (for doctors)
            if ($userType !== 'doctor') {
                throw new Exception("Only doctors can update appointment status");
            }
            
            if (!isset($input['appointment_id']) || !isset($input['status'])) {
                throw new Exception("Appointment ID and status are required");
            }
            
            $appointmentId = intval($input['appointment_id']);
            $status = validateInput($input['status']);
            
            // Validate status
            $allowedStatuses = ['pending', 'confirmed', 'cancelled'];
            if (!in_array($status, $allowedStatuses)) {
                throw new Exception("Invalid status");
            }
            
            // Check if appointment exists and belongs to this doctor
            $checkStmt = $conn->prepare("SELECT id FROM Appointments WHERE id = ? AND doctor_id = ?");
            $checkStmt->bind_param("ii", $appointmentId, $userId);
            $checkStmt->execute();
            $checkStmt->store_result();
            
            if ($checkStmt->num_rows === 0) {
                throw new Exception("Appointment not found or not authorized");
            }
            
            // Update appointment status
            $stmt = $conn->prepare("UPDATE Appointments SET status = ? WHERE id = ?");
            $stmt->bind_param("si", $status, $appointmentId);
            
            if (!$stmt->execute()) {
                throw new Exception("Error updating appointment: " . $stmt->error);
            }
            
            echo json_encode([
                "success" => true,
                "message" => "Appointment status updated successfully"
            ]);
            break;
            
        case 'DELETE':
            // Cancel appointment (for patients)
            if ($userType !== 'patient') {
                throw new Exception("Only patients can cancel appointments");
            }
            
            if (!isset($input['appointment_id'])) {
                throw new Exception("Appointment ID is required");
            }
            
            $appointmentId = intval($input['appointment_id']);
            
            // Check if appointment exists and belongs to this patient
            $checkStmt = $conn->prepare("SELECT id, status FROM Appointments WHERE id = ? AND user_id = ?");
            $checkStmt->bind_param("ii", $appointmentId, $userId);
            $checkStmt->execute();
            $checkResult = $checkStmt->get_result();
            
            if ($checkResult->num_rows === 0) {
                throw new Exception("Appointment not found or not authorized");
            }
            
            $appointment = $checkResult->fetch_assoc();
            
            // Check if appointment can be cancelled
            if ($appointment['status'] === 'cancelled') {
                throw new Exception("Appointment is already cancelled");
            }
            
            // Cancel appointment
            $stmt = $conn->prepare("UPDATE Appointments SET status = 'cancelled' WHERE id = ?");
            $stmt->bind_param("i", $appointmentId);
            
            if (!$stmt->execute()) {
                throw new Exception("Error cancelling appointment: " . $stmt->error);
            }
            
            echo json_encode([
                "success" => true,
                "message" => "Appointment cancelled successfully"
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
    $logger->error("Appointments API error: " . $e->getMessage());
}

// Close database connection
$conn->close();
?> 