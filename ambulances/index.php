<?php
// Note: Included from main `index.php` router.

switch ($method) {
    case 'GET':
        // Get all ambulances or a specific one
        if (isset($path_parts[2])) {
            $id = intval($path_parts[2]);
            $stmt = $conn->prepare("SELECT * FROM Ambulances WHERE id = ?");
            $stmt->bind_param("i", $id);
            $stmt->execute();
            $result = $stmt->get_result()->fetch_assoc();
        } else {
            $result = $conn->query("SELECT * FROM Ambulances")->fetch_all(MYSQLI_ASSOC);
        }
        echo json_encode(["success" => true, "data" => $result]);
        break;

    case 'POST':
        // Create a new ambulance
        $driver_name = validateInput($input['driver_name']);
        $location = validateInput($input['location']);
        $status = validateInput($input['status']); // e.g., 'available'
        $stmt = $conn->prepare("INSERT INTO Ambulances (driver_name, location, status) VALUES (?, ?, ?)");
        $stmt->bind_param("sss", $driver_name, $location, $status);
        $stmt->execute();
        echo json_encode(["success" => true, "message" => "Ambulance created"]);
        break;
        
    default:
        http_response_code(405);
        echo json_encode(["error" => "Method not allowed"]);
        break;
}
?> 