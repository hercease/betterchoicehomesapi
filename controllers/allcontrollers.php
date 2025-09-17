<?php

class Controllers {
    private $db;
	private $allModel;

    public function __construct($db){
        $this->db = $db;
        $this->allModel = new allModels($db);
    }

    public function processLoginMethod(){
        try {

            $email = $this->allModel->sanitizeInput($_POST['email']);
            $password = $this->allModel->sanitizeInput($_POST['password']);
            // Fetch user info
            $fetchuserinfo = $this->allModel->getUserInfo($email);

            if ($fetchuserinfo === null) {
                throw new Exception("Ooops, Invalid email or password");
            }

            // Verify password
            if (!password_verify($password, $fetchuserinfo['password'])) {
                throw new Exception("Ooops, Invalid email or password");
            }

            $value = $this->allModel->encryptCookie($email);

            // Set session variables
            return ["status" => true, "token" => $value];

        } catch (Exception $th) {
            return [
                'status' => false,
                'message' => $th->getMessage()
            ];
        }
    }

    public function processForgotPassword(){
        try{

            $email = $this->allModel->sanitizeInput($_POST['email']);
            $userInfo = $this->allModel->getUserInfo($email);

            if (!$userInfo) {
                throw new Exception("User not found");
            }

            $firstName = $userInfo['firstname'] ?? '';
            $password = $this->allModel->generateRandomPassword(7);
            $newPassword = password_hash($password, PASSWORD_DEFAULT);
            $year = date("Y");

            $stmt = $this->db->prepare("UPDATE users SET password = ? WHERE email = ?");
            $stmt->bind_param("ss", $newPassword, $email);
            $stmt->execute();
            $stmt->close();

            $subject = "Password Reset - Better Choice Homes";

        $message = <<<EMAIL
            <!DOCTYPE html>
            <html lang="en">
            <head>
            <meta charset="UTF-8">
            <title>Password Reset - Better Choice Group Homes</title>
            <style>
                body { font-family: 'Segoe UI', sans-serif; background-color: #f8f9fa; margin: 0; padding: 0; color: #333; }
                .container { max-width: 600px; margin: 30px auto; background-color: #ffffff; border: 1px solid #e0e0e0; border-radius: 8px; overflow: hidden; }
                .header { background-color: #0a3d62; padding: 20px; color: #ffffff; text-align: center; }
                .body { padding: 30px; }
                .body h2 { color: #0a3d62; margin-top: 0; }
                .password-box {
                    background-color: #f1f3f5;
                    padding: 15px;
                    border-radius: 5px;
                    font-size: 18px;
                    font-weight: bold;
                    text-align: center;
                    letter-spacing: 1px;
                    color: #0a3d62;
                    margin: 20px 0;
                }
                .footer { text-align: center; font-size: 13px; color: #888; padding: 20px; }
            </style>
            </head>
            <body>
            <div class="container">
                <div class="header">
                    <h1>Password Reset</h1>
                </div>
                <div class="body">
                    <h2>Hello {$firstName},</h2>
                    <p>You recently requested to reset your password for your Better Choice Homes account.</p>
                    <p>Here is your new temporary password:</p>
                    <div class="password-box">{$password}</div>
                    <p>For your security, please log in and change your password immediately.</p>
                    <p>If you didn’t request this change, please contact our support team right away.</p>
                </div>
                <div class="footer">
                    &copy; {$year} Better Choice Group Homes. All rights reserved.
                </div>
            </div>
            </body>
            </html>
            EMAIL;

            $this->allModel->sendmail($email, $firstName, $message, $subject);

            return [
                'status' => true,
                'message' => 'Password reset email sent successful'
            ];

        } catch(Exception $th){
            return [
                'status' => false,
                'message' => $th->getMessage()
            ];
        }
       

    }

    public function fetchuserDetails(){
        $email = $this->allModel->decryptCookie($this->allModel->sanitizeInput($_POST['email']));
        if (!$this->allModel->getUserInfo($email)) {
            return [
                'status' => false,
                'message' => 'User not found'
            ];
        }
        return ['status' => true, 'message' => 'User found', 'data' => $this->allModel->getUserInfo($email)];
    }

    public function updateProfile(){
        try{

            $email = $this->allModel->decryptCookie($this->allModel->sanitizeInput($_POST['email']));
            if(!$this->allModel->getUserInfo($email)){
                throw new Exception("User not found");
            }
            $userinfo = $this->allModel->getUserInfo($email);
            $input = [];
            $requiredFields = ['address', 'sin', 'emergencyContact', 'dateOfBirth', 'driverlicensenumber', 'driverlicenseexpirationdate', 'transitNumber', 'institutionNumber', 'accountNumber', 'province', 'city', 'postal_code'];
            foreach ($requiredFields as $field) {
                $input[$field] = $this->allModel->sanitizeInput($_POST[$field] ?? '');
                if (empty($input[$field])) {
                    throw new Exception(ucfirst($field) . " is required");
                }
            }

            $this->db->begin_transaction();

            date_default_timezone_set($_POST['timezone'] ?? 'America/Toronto');

            $user_id = intval($userinfo['user_id']);
            $uploadDir =  UPLOAD_URL;

            $stmt = $this->db->prepare("UPDATE user_details SET driver_license_expiry_date = ?, driver_license_number = ?, address = ?, city = ?, province = ?, postal_code = ?, dob = ?, sin = ?, contact_number = ?, transit_number = ?, institution_number = ?, account_number = ? WHERE user_id = ?");
            $stmt->bind_param("ssssssssssssi", $input['driverlicenseexpirationdate'], $input['driverlicensenumber'], $input['address'], $input['city'], $input['province'], $input['postal_code'], $input['dateOfBirth'], $input['sin'], $input['emergencyContact'], $input['transitNumber'], $input['institutionNumber'], $input['accountNumber'], $user_id);
            if (!$stmt->execute()) {
                throw new Exception("User details update failed: " . $stmt->error);
            }
            $stmt->close();

            if (!empty($_FILES['documents']['name']) && isset($_POST['document_tags'])) {
                foreach ($_FILES['documents']['name'] as $index => $name) {
                    if (!$_FILES['documents']['tmp_name'][$index]) continue;

                    // File size check (max 5 MB)
                    if ($_FILES['documents']['size'][$index] > (5 * 1024 * 1024)) {
                        throw new Exception("File $name is larger than 5MB");
                    }

                    // File type check (PDF only)
                    $fileType = mime_content_type($_FILES['documents']['tmp_name'][$index]);
                    if ($fileType !== 'application/pdf') {
                        throw new Exception("File $name must be a PDF");
                    }

                    $tag = $_POST['document_tags'][$index];
                    $safeName = time() . "_" . preg_replace('/[^a-zA-Z0-9\._-]/', '_', $name);
                    $dest = $uploadDir . $safeName;

                    if (!move_uploaded_file($_FILES['documents']['tmp_name'][$index], $dest)) {
                        throw new Exception("Failed to upload document: $name");
                    }

                    $stmt = $this->db->prepare("UPDATE documents SET name = ?, updated_on = NOW() WHERE user_id = ? AND doc_tag = ?");
                    $stmt->bind_param("sis", $safeName, $user_id, $tag);
                    $stmt->execute();
                    $stmt->close();
                }
            }

            if (!empty($_FILES['certificates']['name']) && isset($_POST['certificate_tags'])) {
                foreach ($_FILES['certificates']['name'] as $index => $name) {
                    if (!$_FILES['certificates']['tmp_name'][$index]) continue;

                    // File size check (max 5 MB)
                    if ($_FILES['certificates']['size'][$index] > (5 * 1024 * 1024)) {
                        throw new Exception("Certificate $name is larger than 5MB");
                    }

                    // File type check (PDF only)
                    $fileType = mime_content_type($_FILES['certificates']['tmp_name'][$index]);
                    if ($fileType !== 'application/pdf') {
                        throw new Exception("Certificate $name must be a PDF");
                    }

                    $tag = $_POST['certificate_tags'][$index];
                    $safeName = time() . "_" . preg_replace('/[^a-zA-Z0-9\._-]/', '_', $name);
                    $dest = $uploadDir . $safeName;

                    if (!move_uploaded_file($_FILES['certificates']['tmp_name'][$index], $dest)) {
                        throw new Exception("Failed to upload certificate: $name");
                    }

                    $stmt = $this->db->prepare("UPDATE certificates SET certificate_name = ?, updated_on = NOW() WHERE user_id = ? AND cert_tag = ?");
                    $stmt->bind_param("sis", $safeName, $user_id, $tag);
                    $stmt->execute();
                    $stmt->close();
                }
            }

            $date = date("Y-m-d H:i:m");

            $this->allModel->logActivity($userinfo['email'], $user_id, 'update-profile', 'User updated their profile', $date);

            $this->db->commit();

            return [
                'status' => true,
                'message' => 'Profile updated successfully'
            ];

        }catch(Exception $th){
            $this->db->rollback();
            return [
                'status' => false,
                'message' => $th->getMessage()
            ];  
        }
    }

    public function fetchAllActivities(){
        // Get parameters from request
        $page = $_POST['page'] ?? 1;
        $perPage = $_POST['per_page'] ?? 10;

        $email = $this->allModel->decryptCookie($this->allModel->sanitizeInput($_POST['email'] ?? ''));
            if(!$this->allModel->getUserInfo($email)){
                throw new Exception("User not found");
            }

        // Validate parameters
        $page = max(1, (int)$page);
        $perPage = max(1, min(50, (int)$perPage));
        $offset = ($page - 1) * $perPage;

        // Initialize response array
        $response = [
            'success' => false,
            'message' => '',
            'data' => [],
            'pagination' => []
        ];

        try {
            // Get total count of activities for this user
            $countQuery = "SELECT COUNT(*) AS total FROM activities WHERE user = ?";
            $countStmt = $this->db->prepare($countQuery);
            $countStmt->bind_param('s', $email);
            $countStmt->execute();
            $countResult = $countStmt->get_result();
            $totalRow = $countResult->fetch_assoc();
            $totalItems = $totalRow['total'];
            $totalPages = ceil($totalItems / $perPage);
            $countStmt->close();

            $activities = [];

            // Get paginated activities
            $query = "
                SELECT 
                    id, 
                    action, 
                    description, 
                    date
                FROM activities 
                WHERE user = ?
                ORDER BY id DESC
                LIMIT ? OFFSET ?
            ";
            
            $stmt = $this->db->prepare($query);
            $stmt->bind_param('sii', $email, $perPage, $offset);
            $stmt->execute();
            $result = $stmt->get_result();
            while ($act = $result->fetch_assoc()) {
                $activities[] = [
                    'id' => $act['id'],
                    'action' => $act['action'],
                    'description' => $act['description'],
                    'date'   => date("F j, Y, g:i A", strtotime($act['date']))
                ];
            }

            // Format successful response
            $response['success'] = true;
            $response['data'] = $activities;
            $response['pagination'] = [
                'current_page' => $page,
                'per_page' => $perPage,
                'total_items' => $totalItems,
                'total_pages' => $totalPages,
                'has_next_page' => $page < $totalPages,
                'has_prev_page' => $page > 1,
            ];

            return [
                'status' => true,
                'data' => $response
            ];

            //error_log($response);

        } catch (Exception $e) {
            http_response_code(500);
            $response['message'] = $e->getMessage();
            return [
                'status' => false,
                'message' => $response
            ];  
        } finally {
            $this->db->close();
        }
    }

    public function ChangePassword(){
        
            $timezone = $_POST['timezone'] ?? 'America/Toronto';
            date_default_timezone_set($timezone);

            try {

                $input = [];
                $requiredFields = ['currentPassword', 'newPassword', 'confirmPassword'];
                foreach ($requiredFields as $field) {
                    $input[$field] = $this->allModel->sanitizeInput($_POST[$field] ?? '');
                    if (empty($input[$field])) {
                        throw new Exception(ucfirst($field) . " is required");
                    }
                }

                $email = $this->allModel->decryptCookie($this->allModel->sanitizeInput($_POST['email'] ?? ''));

                if(!$this->allModel->getUserInfo($email)){
                    throw new Exception("User Not found");
                }

                $userInfo = $this->allModel->getUserInfo($email);

                if($input['newPassword'] != $input['confirmPassword']){
                    throw new Exception("Your new password details do not match");
                }

                if (!password_verify($input['currentPassword'], $userInfo['password'])){
                    throw new Exception("Incorrect old Password");
                }

                $newpassword = password_hash($input['newPassword'], PASSWORD_DEFAULT);

                $stmt = $this->db->prepare("UPDATE users SET password = ? WHERE email = ?");
                $stmt->bind_param("ss", $newpassword, $email);
                $stmt->execute();

                return [
                    'status' => true,
                    'message' => 'Password Changed successfully'
                ];

            } catch(Exception $e){

                return [
                    'status' => false,
                    'message' => 'Error: ' . $e->getMessage()
                ];

            }
    }

    public function fetchSchedules(){
        try {
             $email = $this->allModel->decryptCookie($this->allModel->sanitizeInput($_POST['email'] ?? ''));

            if(!$this->allModel->getUserInfo($email)){
                throw new Exception("User Not found");
            }

            $userInfo = $this->allModel->getUserInfo($email);
            $query = "SELECT id, schedule_date AS date, location_name, start_time, end_time, clockin, clockout, pay_per_hour, TIMESTAMPDIFF(HOUR, start_time, end_time) AS total_hours, (TIMESTAMPDIFF(HOUR, start_time, end_time) * pay_per_hour) AS total_pay FROM scheduling WHERE email = '$email'";
            
            $result = $this->db->query($query);

            $schedules = [];
            while ($row = $result->fetch_assoc()) {
                /*$schedules[] = [
                    "id" => $row['id'],
                    "title" => "Shift",
                    "start" => $row['schedule_date'] . "T" . $row['start_time'],
                    "end"   => $row['schedule_date'] . "T" . $row['end_time'],
                    "clockin" => $row['clockin'],
                    "clockout" => $row['clockout'],
                    "pay_per_hour" => $row['pay_per_hour'],
                    "date" => $row['schedule_date'],
                    "location" => $row['location_name'],
                ];*/

                $row['start_time'] = date('h:i A', strtotime($row['start_time']));
                $row['end_time'] = date('h:i A', strtotime($row['end_time']));
                $row['clockin'] = $row['clockin'] ? date('h:i A', strtotime($row['clockin'])) : 'Not clocked in';
                $row['clockout'] = $row['clockout'] ? date('h:i A', strtotime($row['clockout'])) : 'Not clocked out';
                $row['total_pay'] = number_format($row['total_pay'], 2);
                
                $schedules[] = $row;

            }

            return [
                'status' => true,
                'data'  => $schedules
            ];

        } catch (Exception $th) {
            return [
                'status' => false,
                'message' => 'Error: ' . $th->getMessage()
            ];
        }
       
    }

    public function fetchMonthlySchedules() {
        try {
            $email = $this->allModel->decryptCookie(
                $this->allModel->sanitizeInput($_POST['email'] ?? '')
            );

            if (!$this->allModel->getUserInfo($email)) {
                throw new Exception("User Not found");
            }

            $month = $_POST['month'] ?? date('Y-m');

            $query = "SELECT 
                        id, 
                        schedule_date AS date, 
                        DATE_FORMAT(start_time, '%h:%i %p') AS start_time,
                        DATE_FORMAT(end_time, '%h:%i %p') AS end_time,
                        DATE_FORMAT(clockin, '%h:%i %p') AS clockin, 
                        DATE_FORMAT(clockout, '%h:%i %p') AS clockout, 
                        pay_per_hour,
                        location_name AS location,
                        shift_type,
                        overnight_type,

                        -- Total scheduled hours
                        ROUND(
                            CASE 
                                WHEN end_time <= start_time 
                                THEN TIMESTAMPDIFF(SECOND, start_time, DATE_ADD(end_time, INTERVAL 1 DAY)) / 3600
                                ELSE TIMESTAMPDIFF(SECOND, start_time, end_time) / 3600
                            END, 2
                        ) AS total_hours,

                        -- Expected pay
                        FORMAT(
                            (CASE 
                                WHEN end_time <= start_time 
                                THEN TIMESTAMPDIFF(SECOND, start_time, DATE_ADD(end_time, INTERVAL 1 DAY)) / 3600
                                ELSE TIMESTAMPDIFF(SECOND, start_time, end_time) / 3600
                            END * pay_per_hour), 2
                        ) AS expected_pay,

                        -- Actual worked hours
                        ROUND(
                            CASE 
                                WHEN clockout IS NOT NULL AND clockin IS NOT NULL AND clockout <= clockin
                                THEN TIMESTAMPDIFF(SECOND, clockin, DATE_ADD(clockout, INTERVAL 1 DAY)) / 3600
                                ELSE TIMESTAMPDIFF(SECOND, clockin, clockout) / 3600
                            END, 2
                        ) AS hours_worked,

                        -- Total pay based on actual worked hours
                        FORMAT(
                            (CASE 
                                WHEN clockout IS NOT NULL AND clockin IS NOT NULL AND clockout <= clockin
                                THEN TIMESTAMPDIFF(SECOND, clockin, DATE_ADD(clockout, INTERVAL 1 DAY)) / 3600
                                ELSE TIMESTAMPDIFF(SECOND, clockin, clockout) / 3600
                            END * pay_per_hour), 2
                        ) AS total_pay

                    FROM scheduling
                    WHERE email = ? 
                    AND DATE_FORMAT(schedule_date, '%Y-%m') = ?
                    ORDER BY schedule_date, start_time";

            $stmt = $this->db->prepare($query);
            $stmt->bind_param('ss', $email, $month);
            $stmt->execute();
            $result = $stmt->get_result();

            $schedules = [];
            $markedDates = [];

            while ($row = $result->fetch_assoc()) {
                $date = $row['date'];

                // Add to schedules list
                $schedules[] = $row;

                // Mark date on calendar
                if (!isset($markedDates[$date])) {
                    $markedDates[$date] = [
                        'marked' => true,
                        'dotColor' => '#4CAF50',
                        'count' => 1
                    ];
                } else {
                    $markedDates[$date]['count']++;
                }
            }

            return [
                'status' => true,
                'data' => [
                    'schedules' => $schedules,
                    'marked_dates' => $markedDates
                ]
            ];

        } catch (Exception $th) {
            return [
                'status' => false,
                'message' => 'Error: ' . $th->getMessage()
            ];
        }
    }

    public function Attendance() {
        try {
            $email = $this->allModel->decryptCookie(
                $this->allModel->sanitizeInput($_POST['email'] ?? '')
            );

            $timezone = $_POST['timezone'] ?? 'America/Toronto';
            date_default_timezone_set($timezone);
            $time = date('H:i:s');
            $date = date('Y-m-d');
            $action = strtolower($_POST['action'] ?? '');
            $long = floatval($_POST['longitude'] ?? 0);
            $lat  = floatval($_POST['latitude'] ?? 0);

            // get user_id
            $userinfo = $this->allModel->getUserInfo($email);

            if (!$userinfo) {
                throw new Exception("User not found.");
            }

            // check schedule
            $sql = "SELECT id, clockin, clockout, start_time, end_time, location_id,
                    CASE 
                    WHEN end_time <= start_time 
                        THEN TIMESTAMPDIFF(SECOND, start_time, DATE_ADD(end_time, INTERVAL 1 DAY))
                        ELSE TIMESTAMPDIFF(SECOND, start_time, end_time)
                    END AS total_seconds 
                    FROM scheduling 
                    WHERE email = ? AND schedule_date = ?";
            $stmt = $this->db->prepare($sql);
            $stmt->bind_param("ss", $email, $date);
            $stmt->execute();
            $result = $stmt->get_result();
            $schedule = $result->fetch_assoc();
            $stmt->close();

            if (!$schedule) {
                throw new Exception("No schedule found for today");
            }

            // Convert schedule times to DateTime objects for comparison
            $currentTimeObj = DateTime::createFromFormat('H:i:s', $time);
            $scheduleEndTimeObj = DateTime::createFromFormat('H:i:s', $schedule['end_time']);
            
            // Handle overnight schedules (if end time is earlier than start time, it spans to next day)
            if ($schedule['end_time'] <= $schedule['start_time']) {
                // For overnight schedules, add 1 day to end time for comparison
                $scheduleEndTimeObj->modify('+1 day');
            }

            if ($action === "clockin") {
                // Check if current time is beyond scheduled end time
                if ($currentTimeObj > $scheduleEndTimeObj) {
                    throw new Exception("Cannot clock in - your scheduled shift has already ended.");
                }

                if (!empty($schedule['clockout'])) {
                    throw new Exception("You have already clocked out today");
                }

                if (!empty($schedule['clockin'])) {
                    throw new Exception("You have already clocked in today");
                }

                $distance = 0;
                $longitude = 0;
                $latitude = 0;
                // check distance
                $sql = "SELECT ST_Distance_Sphere(
                            POINT(latitude, longitude),
                            POINT(?, ?)
                        ) AS distance,
                        longitude,
                        latitude
                        FROM locations WHERE id = ?";
                $stmt = $this->db->prepare($sql);
                $stmt->bind_param("ddi", $long, $lat, $schedule['location_id']);
                $stmt->execute();
                $result = $stmt->get_result();
                $locationData = $result->fetch_assoc();
                $distance = $locationData['distance'] ?? null;
                $longitude = $locationData['longitude'] ?? null;
                $latitude = $locationData['latitude'] ?? null;
                $stmt->close();

                // Debug log before checking distance
                error_log("Frontend coordinates: longitude={$long}, latitude={$lat}");
                error_log("Database coordinates: longitude={$locationData['longitude']}, latitude={$locationData['latitude']}");
                error_log("Calculated distance (meters): " . ($distance ?? 'NULL'));

                if ($distance > 5) {
                    throw new Exception("You are not within your appointment location yet");
                }

                // update clockin
                $sql = "UPDATE scheduling SET clockin = ? WHERE id = ?";
                $stmt = $this->db->prepare($sql);
                $stmt->bind_param("si", $time, $schedule['id']);
                $stmt->execute();
                $stmt->close();

                $this->allModel->logActivity($userinfo['email'], $userinfo['user_id'], 'check-in', 'Clock-in successful at ' . $time, $date);

                return [
                    'status' => true,
                    'message' => 'Clock-in successful at ' . $time,
                    'latitude' => $latitude,
                    'longitude' => $longitude,
                    'work_seconds' => $schedule['total_seconds']
                ];
            }

            if ($action === "clockout") {
                if (empty($schedule['clockin'])) {
                    return [
                        'status' => false,
                        'message' => 'You have not clocked in yet'
                    ];
                }
                if (!empty($schedule['clockout'])) {
                    return [
                        'status' => false,
                        'message' => 'You have already clocked out today'
                    ];
                }

                // update clockout
                $sql = "UPDATE scheduling SET clockout = ? WHERE id = ?";
                $stmt = $this->db->prepare($sql);
                $stmt->bind_param("si", $time, $schedule['id']);
                $stmt->execute();
                $stmt->close();

                $this->allModel->logActivity($userinfo['email'], $userinfo['user_id'], 'check-out', 'Clock-out successful at ' . $time, $date);

                return [
                    'status' => true,
                    'message' => 'Clock-out successful at ' . $time
                ];
            }

            return [
                'status' => false,
                'message' => 'Invalid action specified'
            ];

        } catch (Exception $th) {
            return [
                'status' => false,
                'message' => 'Error: ' . $th->getMessage()
            ];
        }
    }

    public function saveNotification(){

        $token = $this->allModel->sanitizeInput($_POST['token']);
        $email = $this->allModel->decryptCookie(
            $this->allModel->sanitizeInput($_POST['email'] ?? '')
            );
        
        try {
            // get user_id
            $userinfo = $this->allModel->getUserInfo($email);

            if (!$userinfo) {
                throw new Exception("User not found.");
            }

            // Check if email exists in notification_token table
            $checkStmt = $this->db->prepare("SELECT email FROM notification_token WHERE email = ?");
            $checkStmt->bind_param("s", $email);
            $checkStmt->execute();
            $result = $checkStmt->get_result();

            if ($result->num_rows > 0) {
                // Update existing token
                $updateStmt = $this->db->prepare("UPDATE notification_token SET token = ? WHERE email = ?");
                $updateStmt->bind_param("ss", $token, $email);
                $updateStmt->execute();
                $updateStmt->close();
            } else {
                // Insert new token
                $insertStmt = $this->db->prepare("INSERT INTO notification_token (email, token) VALUES (?, ?)");
                $insertStmt->bind_param("ss", $email, $token);
                $insertStmt->execute();
                $insertStmt->close();
            }

            return [
                'status' => true,
                'message' => 'Notification token saved successfully'
            ];

        } catch (Exception $e) {
            return [
                'status' => false,
                'message' => $e->getMessage()
            ];
        }

    }




}