<?php
// Note: Included from main `index.php` router.

switch ($method) {
    case 'GET':
        // Get all ambulance requests
        $result = $conn->query("SELECT * FROM AmbulanceRequests")->fetch_all(MYSQLI_ASSOC);
        echo json_encode(["success" => true, "data" => $result]);
        break;

    case 'POST':
        // Create a new ambulance request
        $user_id = intval($input['user_id']);
        $location = validateInput($input['location']);
        $status = 'pending'; // Default status
        $stmt = $conn->prepare("INSERT INTO AmbulanceRequests (user_id, location, status) VALUES (?, ?, ?)");
        $stmt->bind_param("is", $user_id, $location, $status);
        $stmt->execute();
        echo json_encode(["success" => true, "message" => "Ambulance request submitted"]);
        break;
        
    default:
        http_response_code(405);
        echo json_encode(["error" => "Method not allowed"]);
        break;
}
?> 