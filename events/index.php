<?php
header("Content-Type: application/json; charset=UTF-8");

// Include required files
require_once '../config.php';
require_once '../cors.php';

// Get request method and path
$method = $_SERVER['REQUEST_METHOD'];
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$path = trim(str_replace('/api/events', '', $path), '/');

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
                // Get specific doctor events
                $doctorId = intval($path);
                
                // Check if doctor exists
                $doctorStmt = $conn->prepare("SELECT id, name FROM Doctors WHERE id = ?");
                $doctorStmt->bind_param("i", $doctorId);
                $doctorStmt->execute();
                $doctorResult = $doctorStmt->get_result();
                
                if ($doctorResult->num_rows === 0) {
                    throw new Exception("Doctor not found");
                }
                
                $doctor = $doctorResult->fetch_assoc();
                
                // Get doctor events
                $stmt = $conn->prepare("SELECT e.*, d.name as doctor_name, d.specialization 
                                       FROM Events e 
                                       JOIN Doctors d ON e.doctor_id = d.id 
                                       WHERE e.doctor_id = ? AND e.date >= CURDATE()
                                       ORDER BY e.date ASC, e.start_time ASC");
                $stmt->bind_param("i", $doctorId);
                $stmt->execute();
                $result = $stmt->get_result();
                
                $events = [];
                while ($row = $result->fetch_assoc()) {
                    $events[] = $row;
                }
                
                echo json_encode([
                    "success" => true,
                    "doctor" => $doctor,
                    "events" => $events
                ]);
            } else {
                // Get all events (for admin) or user's events
                $page = isset($_GET['page']) ? max(1, intval($_GET['page'])) : 1;
                $limit = isset($_GET['limit']) ? min(100, max(1, intval($_GET['limit']))) : 10;
                $date = isset($_GET['date']) ? trim($_GET['date']) : '';
                $doctorId = isset($_GET['doctor_id']) ? intval($_GET['doctor_id']) : null;
                
                $where = [];
                $params = [];
                $types = "";
                
                if ($userType === 'doctor') {
                    $where[] = "e.doctor_id = ?";
                    $params[] = $userId;
                    $types .= "i";
                } elseif ($userType === 'admin') {
                    // Admin can see all events
                } else {
                    // Patient can see all events
                }
                
                if ($date) {
                    $where[] = "e.date = ?";
                    $params[] = $date;
                    $types .= "s";
                }
                
                if ($doctorId) {
                    $where[] = "e.doctor_id = ?";
                    $params[] = $doctorId;
                    $types .= "i";
                }
                
                $whereClause = !empty($where) ? 'WHERE ' . implode(' AND ', $where) : '';
                
                // Get total count
                $countSql = "SELECT COUNT(*) as total FROM Events e $whereClause";
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
                
                // Get events with pagination
                $sql = "SELECT e.*, d.name as doctor_name, d.specialization, d.email as doctor_email 
                        FROM Events e 
                        JOIN Doctors d ON e.doctor_id = d.id 
                        $whereClause 
                        ORDER BY e.date ASC, e.start_time ASC 
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
                $events = [];
                while ($row = $result->fetch_assoc()) {
                    $events[] = $row;
                }
                
                echo json_encode([
                    "success" => true,
                    "events" => $events,
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
            // Create new event (for doctors only)
            if ($userType !== 'doctor') {
                throw new Exception("Only doctors can create events");
            }
            
            if (!isset($input['date']) || !isset($input['start_time']) || !isset($input['end_time'])) {
                throw new Exception("Date, start time, and end time are required");
            }
            
            $date = validateInput($input['date']);
            $startTime = validateInput($input['start_time']);
            $endTime = validateInput($input['end_time']);
            $title = isset($input['title']) ? validateInput($input['title']) : '';
            $description = isset($input['description']) ? validateInput($input['description']) : '';
            $location = isset($input['location']) ? validateInput($input['location']) : '';
            $maxPatients = isset($input['max_patients']) ? intval($input['max_patients']) : 10;
            
            // Validate date format
            if (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $date)) {
                throw new Exception("Invalid date format. Use YYYY-MM-DD");
            }
            
            // Validate time format
            if (!preg_match('/^\d{2}:\d{2}:\d{2}$/', $startTime) || !preg_match('/^\d{2}:\d{2}:\d{2}$/', $endTime)) {
                throw new Exception("Invalid time format. Use HH:MM:SS");
            }
            
            // Check if date is in the future
            if (strtotime($date) < strtotime(date('Y-m-d'))) {
                throw new Exception("Event date must be in the future");
            }
            
            // Check if start time is before end time
            if (strtotime($startTime) >= strtotime($endTime)) {
                throw new Exception("Start time must be before end time");
            }
            
            // Check if event slot is available
            $slotStmt = $conn->prepare("SELECT id FROM Events WHERE doctor_id = ? AND date = ? AND 
                                       ((start_time <= ? AND end_time > ?) OR 
                                        (start_time < ? AND end_time >= ?) OR 
                                        (start_time >= ? AND end_time <= ?))");
            $slotStmt->bind_param("isssssss", $userId, $date, $startTime, $startTime, $endTime, $endTime, $startTime, $endTime);
            $slotStmt->execute();
            $slotStmt->store_result();
            
            if ($slotStmt->num_rows > 0) {
                throw new Exception("Event slot conflicts with existing event");
            }
            
            // Insert event
            $stmt = $conn->prepare("INSERT INTO Events (doctor_id, title, description, date, start_time, end_time, location, max_patients, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW())");
            $stmt->bind_param("issssssi", $userId, $title, $description, $date, $startTime, $endTime, $location, $maxPatients);
            
            if (!$stmt->execute()) {
                throw new Exception("Error creating event: " . $stmt->error);
            }
            
            $eventId = $conn->insert_id;
            
            echo json_encode([
                "success" => true,
                "message" => "Event created successfully",
                "event_id" => $eventId,
                "event" => [
                    "id" => $eventId,
                    "doctor_id" => $userId,
                    "title" => $title,
                    "description" => $description,
                    "date" => $date,
                    "start_time" => $startTime,
                    "end_time" => $endTime,
                    "location" => $location,
                    "max_patients" => $maxPatients
                ]
            ]);
            break;

        case 'PUT':
            // Update event (for doctors only)
            if ($userType !== 'doctor') {
                throw new Exception("Only doctors can update events");
            }
            
            if (!isset($input['event_id'])) {
                throw new Exception("Event ID is required");
            }
            
            $eventId = intval($input['event_id']);
            
            // Check if event exists and belongs to this doctor
            $checkStmt = $conn->prepare("SELECT id FROM Events WHERE id = ? AND doctor_id = ?");
            $checkStmt->bind_param("ii", $eventId, $userId);
            $checkStmt->execute();
            $checkStmt->store_result();
            
            if ($checkStmt->num_rows === 0) {
                throw new Exception("Event not found or not authorized");
            }
            
            // Build update query dynamically
            $updateFields = [];
            $updateParams = [];
            $updateTypes = "";
            
            if (isset($input['title'])) {
                $updateFields[] = "title = ?";
                $updateParams[] = validateInput($input['title']);
                $updateTypes .= "s";
            }
            
            if (isset($input['description'])) {
                $updateFields[] = "description = ?";
                $updateParams[] = validateInput($input['description']);
                $updateTypes .= "s";
            }
            
            if (isset($input['date'])) {
                $updateFields[] = "date = ?";
                $updateParams[] = validateInput($input['date']);
                $updateTypes .= "s";
            }
            
            if (isset($input['start_time'])) {
                $updateFields[] = "start_time = ?";
                $updateParams[] = validateInput($input['start_time']);
                $updateTypes .= "s";
            }
            
            if (isset($input['end_time'])) {
                $updateFields[] = "end_time = ?";
                $updateParams[] = validateInput($input['end_time']);
                $updateTypes .= "s";
            }
            
            if (isset($input['location'])) {
                $updateFields[] = "location = ?";
                $updateParams[] = validateInput($input['location']);
                $updateTypes .= "s";
            }
            
            if (isset($input['max_patients'])) {
                $updateFields[] = "max_patients = ?";
                $updateParams[] = intval($input['max_patients']);
                $updateTypes .= "i";
            }
            
            if (empty($updateFields)) {
                throw new Exception("No fields to update");
            }
            
            $updateFields[] = "updated_at = NOW()";
            
            $sql = "UPDATE Events SET " . implode(', ', $updateFields) . " WHERE id = ?";
            $updateParams[] = $eventId;
            $updateTypes .= "i";
            
            $stmt = $conn->prepare($sql);
            $stmt->bind_param($updateTypes, ...$updateParams);
            
            if (!$stmt->execute()) {
                throw new Exception("Error updating event: " . $stmt->error);
            }
            
            echo json_encode([
                "success" => true,
                "message" => "Event updated successfully"
            ]);
            break;

        case 'DELETE':
            // Delete event (for doctors only)
            if ($userType !== 'doctor') {
                throw new Exception("Only doctors can delete events");
            }
            
            if (!isset($input['event_id'])) {
                throw new Exception("Event ID is required");
            }
            
            $eventId = intval($input['event_id']);
            
            // Check if event exists and belongs to this doctor
            $checkStmt = $conn->prepare("SELECT id FROM Events WHERE id = ? AND doctor_id = ?");
            $checkStmt->bind_param("ii", $eventId, $userId);
            $checkStmt->execute();
            $checkStmt->store_result();
            
            if ($checkStmt->num_rows === 0) {
                throw new Exception("Event not found or not authorized");
            }
            
            // Delete event
            $stmt = $conn->prepare("DELETE FROM Events WHERE id = ?");
            $stmt->bind_param("i", $eventId);
            
            if (!$stmt->execute()) {
                throw new Exception("Error deleting event: " . $stmt->error);
            }
            
            echo json_encode([
                "success" => true,
                "message" => "Event deleted successfully"
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