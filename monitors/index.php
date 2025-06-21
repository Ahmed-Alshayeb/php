<?php
// Note: Included from main `index.php` router.

switch ($method) {
    case 'GET':
        // Get heart rate data for a specific user
        if (isset($_GET['user_id'])) {
            $user_id = intval($_GET['user_id']);
            $stmt = $conn->prepare("SELECT * FROM HeartRateMonitors WHERE user_id = ? ORDER BY timestamp DESC");
            $stmt->bind_param("i", $user_id);
            $stmt->execute();
            $result = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
            echo json_encode(["success" => true, "data" => $result]);
        } else {
            http_response_code(400);
            echo json_encode(["error" => "User ID is required"]);
        }
        break;

    case 'POST':
        // Create a new heart rate reading
        $user_id = intval($input['user_id']);
        $heart_rate = intval($input['heart_rate']);
        $stmt = $conn->prepare("INSERT INTO HeartRateMonitors (user_id, heart_rate) VALUES (?, ?)");
        $stmt->bind_param("ii", $user_id, $heart_rate);
        $stmt->execute();
        echo json_encode(["success" => true, "message" => "Heart rate recorded"]);
        break;
        
    default:
        http_response_code(405);
        echo json_encode(["error" => "Method not allowed"]);
        break;
}
?> 