<?php
// Note: This file is included from the main `index.php` router.
// All required files and database connection are already available.

// Handle different HTTP methods
switch ($method) {
    case 'GET':
        // Logic to get pharmacies
        if (isset($path_parts[2])) {
            // Get a specific pharmacy by ID
            $id = intval($path_parts[2]);
            $stmt = $conn->prepare("SELECT * FROM Pharmacies WHERE id = ?");
            $stmt->bind_param("i", $id);
            $stmt->execute();
            $result = $stmt->get_result()->fetch_assoc();
            echo json_encode(["success" => true, "data" => $result]);
        } else {
            // Get all pharmacies
            $result = $conn->query("SELECT * FROM Pharmacies");
            $pharmacies = $result->fetch_all(MYSQLI_ASSOC);
            echo json_encode(["success" => true, "data" => $pharmacies]);
        }
        break;

    case 'POST':
        // Logic to create a new pharmacy
        $name = validateInput($input['name']);
        $location = validateInput($input['location']);
        $stmt = $conn->prepare("INSERT INTO Pharmacies (name, location) VALUES (?, ?)");
        $stmt->bind_param("ss", $name, $location);
        $stmt->execute();
        echo json_encode(["success" => true, "message" => "Pharmacy created"]);
        break;

    case 'PUT':
        // Logic to update a pharmacy
        parse_str(file_get_contents("php://input"), $put_vars);
        $id = intval($path_parts[2]);
        $name = validateInput($put_vars['name']);
        $location = validateInput($put_vars['location']);
        $stmt = $conn->prepare("UPDATE Pharmacies SET name = ?, location = ? WHERE id = ?");
        $stmt->bind_param("ssi", $name, $location, $id);
        $stmt->execute();
        echo json_encode(["success" => true, "message" => "Pharmacy updated"]);
        break;

    case 'DELETE':
        // Logic to delete a pharmacy
        $id = intval($path_parts[2]);
        $stmt = $conn->prepare("DELETE FROM Pharmacies WHERE id = ?");
        $stmt->bind_param("i", $id);
        $stmt->execute();
        echo json_encode(["success" => true, "message" => "Pharmacy deleted"]);
        break;

    default:
        http_response_code(405);
        echo json_encode(["error" => "Method not allowed"]);
        break;
}
?> 