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
            return ["status" => true, "token" => $value, "isActive" => $fetchuserinfo['isActive']];

        } catch (Exception $th) {
            return [
                'status' => false,
                'message' => $th->getMessage()
            ];
        }
    }

    public function processFingerprintLogin(){
        try {

            $email = $this->allModel->sanitizeInput($_POST['email']);

            error_log("Fingerprint login attempt for email: " . $email);

            // Fetch user info
            $fetchuserinfo = $this->allModel->getUserInfo($email);

            if ($fetchuserinfo === null) {
                throw new Exception("Ooops, User not found");
            }

            $value = $this->allModel->encryptCookie($email);

            // Set session variables
            return ["status" => true, "token" => $value, "isActive" => $fetchuserinfo['isActive']];

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
                    <p>If you did not request this change, please contact our support team right away.</p>
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
        try {
            $email = $this->allModel->decryptCookie($this->allModel->sanitizeInput($_POST['email']));
            $userinfo = $this->allModel->getUserInfo($email);
            if (!$userinfo) throw new Exception("User not found");

            $user_id = intval($userinfo['user_id']);
            $uploadDir = UPLOAD_URL;
            
            // Set timezone
            date_default_timezone_set($_POST['timezone'] ?? 'America/Toronto');

            $requiredFields = [
                'address','sin','emergencyContact','dateOfBirth','driverlicensenumber',
                'driverlicenseexpirationdate','transitNumber','institutionNumber',
                'accountNumber','province','city','postal_code'
            ];

            $input = [];
            foreach ($requiredFields as $field) {
                $input[$field] = $this->allModel->sanitizeInput(trim($_POST[$field] ?? ''));
                if ($input[$field] === '') throw new Exception(ucfirst($field)." is required");
            }

            // ========== CUMULATIVE FILE SIZE VALIDATION ==========
            $maxCumulativeSize = 30 * 1024 * 1024; // 30MB in bytes
            $totalFileSize = 0;

            // Calculate total size of all files being uploaded
            $calculateTotalSize = function($files) use (&$totalFileSize) {
                if (!empty($files['size'])) {
                    foreach ($files['size'] as $size) {
                        if ($size > 0) {
                            $totalFileSize += $size;
                        }
                    }
                }
            };

            // Calculate for both document and certificate uploads
            if (!empty($_FILES['documents']['name'])) {
                $calculateTotalSize($_FILES['documents']);
            }
            
            if (!empty($_FILES['certificates']['name'])) {
                $calculateTotalSize($_FILES['certificates']);
            }

            // Check if cumulative size exceeds limit
            if ($totalFileSize > $maxCumulativeSize) {
                $cumulativeSizeMB = round($totalFileSize / (1024 * 1024), 2);
                throw new Exception("Total upload size ({$cumulativeSizeMB}MB) exceeds the 30MB limit. Please reduce file sizes or upload fewer files.");
            }
            // ========== END CUMULATIVE VALIDATION ==========

            $this->db->begin_transaction();

            // Update user details
            $stmt = $this->db->prepare("UPDATE user_details 
                SET driver_license_expiry_date=?, driver_license_number=?, address=?, city=?, province=?, postal_code=?, dob=?, sin=?, contact_number=?, transit_number=?, institution_number=?, account_number=? 
                WHERE user_id=?");
            $stmt->bind_param("ssssssssssssi", 
                $input['driverlicenseexpirationdate'], $input['driverlicensenumber'], 
                $input['address'], $input['city'], $input['province'], $input['postal_code'], 
                $input['dateOfBirth'], $input['sin'], $input['emergencyContact'], 
                $input['transitNumber'], $input['institutionNumber'], $input['accountNumber'], 
                $user_id
            );
            $stmt->execute();
            $stmt->close();

            $finfo = finfo_open(FILEINFO_MIME_TYPE);
            $timestamp = time();

            // Batch upload handler (updated to use the same cumulative check)
            $handleUploads = function($files, $tags, $table, $column, $tagColumn) use ($uploadDir, $user_id, $finfo, $timestamp) {
                $updates = [];
                
                foreach ($files['name'] as $index => $name) {
                    if (!$files['tmp_name'][$index]) continue;
                    
                    // Individual file size check (keep this for per-file validation)
                    if ($files['size'][$index] > 5 * 1024 * 1024) 
                        throw new Exception("$name exceeds 5MB limit");
                    
                    $fileType = finfo_file($finfo, $files['tmp_name'][$index]);
                    if ($fileType !== 'application/pdf') 
                        throw new Exception("$name must be a PDF file");

                    $safeName = "{$timestamp}_{$index}_" . bin2hex(random_bytes(4)) . "_" . 
                            preg_replace('/[^a-zA-Z0-9\._-]/', '_', $name);
                    $dest = $uploadDir . $safeName;
                    
                    if (!move_uploaded_file($files['tmp_name'][$index], $dest))
                        throw new Exception("Failed to move uploaded file: $name");

                    $updates[] = ['name' => $safeName, 'tag' => $tags[$index]];
                }

                // Batch update if we have files
                if (!empty($updates)) {
                    $this->batchUpdateFiles($updates, $user_id, $table, $column, $tagColumn);
                }
            };

            if (!empty($_FILES['documents']['name']) && isset($_POST['document_tags'])) {
                $handleUploads($_FILES['documents'], $_POST['document_tags'], 'documents', 'name', 'doc_tag');
            }

            if (!empty($_FILES['certificates']['name']) && isset($_POST['certificate_tags'])) {
                $handleUploads($_FILES['certificates'], $_POST['certificate_tags'], 'certificates', 'certificate_name', 'cert_tag');
            }

            finfo_close($finfo);

            $this->allModel->logActivity($userinfo['email'], $user_id, 'update-profile', 'User updated profile', date("Y-m-d H:i:s"));

            $this->db->commit();
            return ['status'=>true, 'message'=>'Profile updated successfully'];

        } catch(Exception $th) {
            $this->db->rollback();
            return ['status'=>false, 'message'=>$th->getMessage()];
        }
    }
    
    /**
     * Batch update files in database using CASE statements
     */
    private function batchUpdateFiles(array $files, int $user_id, string $table, string $column, string $tagColumn): void {
        if (empty($files)) return;
    
        $cases = [];
        $params = [];
        $tags = [];
        
        // Build CASE statements and parameters
        foreach ($files as $file) {
            $cases[] = "WHEN ? THEN ?";
            $params[] = $file['tag'];
            $params[] = $file['name'];
            $tags[] = $file['tag'];
        }
        
        // Build the IN clause for tags
        $tagsIn = implode(',', array_fill(0, count($tags), '?'));
        
        // Combine all parameters
        $params = array_merge($params, $tags);
        $params[] = $user_id;
        
        // Build the SQL query
        $sql = "UPDATE {$table} SET {$column} = CASE {$tagColumn} 
                " . implode(' ', $cases) . "
                END, updated_on = NOW() 
                WHERE {$tagColumn} IN ({$tagsIn}) AND user_id = ?";
        
        $stmt = $this->db->prepare($sql);
        if (!$stmt) {
            throw new Exception("Failed to prepare batch update statement");
        }
        
        // Build types string: 'ss' for each file + 's' for each tag + 'i' for user_id
        $types = str_repeat('ss', count($files)) . str_repeat('s', count($tags)) . 'i';
        $stmt->bind_param($types, ...$params);
        
        if (!$stmt->execute()) {
            throw new Exception("Batch update failed: " . $stmt->error);
        }
        
        $stmt->close();
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
                    'message' => $e->getMessage()
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
                'message' => $th->getMessage()
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
                'message' => $th->getMessage()
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

            // FETCH SCHEDULE WITH SHIFT TYPE
            $sql = "SELECT id, clockin, clockout, start_time, end_time, location_id, shift_type, schedule_date
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

            // -----------------------------------------
            // ✅ CORRECTED TOTAL SECONDS CALCULATION
            // -----------------------------------------

            $work_seconds = $this->calculateScheduledSeconds(
                $schedule['schedule_date'],
                $schedule['start_time'],
                $schedule['end_time'],
                $schedule['shift_type'] ?? 'day'
            );
            // -----------------------------------------

            // Convert schedule times to DateTime objects
            $currentTimeObj = DateTime::createFromFormat('H:i:s', $time);
            $scheduleEndTimeObj = DateTime::createFromFormat('H:i:s', $schedule['end_time']);
            $scheduleStartTimeObj = DateTime::createFromFormat('H:i:s', $schedule['start_time']);

            // For comparison, we need full DateTime objects with date
            $currentDateTime = new DateTime($date . ' ' . $time);
            $scheduleStartDateTime = new DateTime($schedule['schedule_date'] . ' ' . $schedule['start_time']);
            $scheduleEndDateTime = new DateTime($schedule['schedule_date'] . ' ' . $schedule['end_time']);
            
            // Adjust end datetime for overnight shifts
            if ($schedule['shift_type'] === 'overnight') {
                $scheduleEndDateTime->modify('+1 day');
            } 
            // Also handle if end time is earlier than start time
            elseif (strtotime($schedule['end_time']) <= strtotime($schedule['start_time'])) {
                $scheduleEndDateTime->modify('+1 day');
            }

            // ============================
            // CLOCK IN
            // ============================
            if ($action === "clockin") {
                // Check if shift has already ended
                if ($currentDateTime > $scheduleEndDateTime) {
                    throw new Exception("Cannot clock in - your scheduled shift has already ended.");
                }

                // Check if too early to clock in (optional - 15 minutes before shift)
                $earliestClockIn = clone $scheduleStartDateTime;
                $earliestClockIn->modify('-15 minutes');
                if ($currentDateTime < $earliestClockIn) {
                    throw new Exception("Cannot clock in more than 15 minutes before your scheduled shift.");
                }

                if (!empty($schedule['clockout'])) {
                    throw new Exception("You have already clocked out today");
                }

                if (!empty($schedule['clockin'])) {
                    throw new Exception("You have already clocked in today");
                }

                // Distance calculation
                $sql = "SELECT ST_Distance_Sphere(
                            POINT(longitude, latitude),
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
                $stmt->close();

                if (($locationData['distance'] ?? 1000) > 40) {
                    throw new Exception("You are not within your appointment location yet");
                }

                // Update clock-in
                $sql = "UPDATE scheduling SET clockin = ? WHERE id = ?";
                $stmt = $this->db->prepare($sql);
                $stmt->bind_param("si", $time, $schedule['id']);
                $stmt->execute();
                $stmt->close();

                $this->allModel->logActivity(
                    $userinfo['email'], 
                    $userinfo['user_id'], 
                    'check-in', 
                    'Clock-in successful at ' . $time, 
                    $date
                );

                return [
                    'status' => true,
                    'message' => 'Clock-in successful at ' . $time,
                    'latitude' => $locationData['latitude'] ?? null,
                    'longitude' => $locationData['longitude'] ?? null,
                    'work_seconds' => $work_seconds // ✅ Correctly calculated
                ];
            }

            // ============================
            // CLOCK OUT
            // ============================
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

                // Check if it's too early to clock out (optional)
                if ($currentDateTime < $scheduleEndDateTime) {
                    // Allow early clockout with warning if shift end time hasn't passed
                    throw new Exception("You can not clock out before your scheduled shift end time.");
                }

                // Update clock-out
                $sql = "UPDATE scheduling SET clockout = ? WHERE id = ?";
                $stmt = $this->db->prepare($sql);
                $stmt->bind_param("si", $time, $schedule['id']);
                $stmt->execute();
                $stmt->close();

                // Calculate actual worked seconds
                $clockinDateTime = new DateTime($date . ' ' . $schedule['clockin']);
                $clockoutDateTime = new DateTime($date . ' ' . $time);
                $actualWorkedSeconds = $clockoutDateTime->getTimestamp() - $clockinDateTime->getTimestamp();

                $this->allModel->logActivity(
                    $userinfo['email'], 
                    $userinfo['user_id'], 
                    'check-out', 
                    'Clock-out successful at ' . $time, 
                    $date
                );

                return [
                    'status' => true,
                    'message' => 'Clocked-out successfully',
                    'work_seconds' => $work_seconds,
                    'worked_seconds' => $actualWorkedSeconds
                ];
            }

            // Invalid action
            return [
                'status' => false,
                'message' => 'Invalid action specified'
            ];

        } catch (Exception $th) {
            return [
                'status' => false,
                'message' => $th->getMessage()
            ];
        }
    }

    public function calculateScheduledSeconds($scheduleDate, $startTime, $endTime, $shiftType) {
        if (empty($scheduleDate) || empty($startTime) || empty($endTime)) {
            return 0;
        }
        
        // Combine date with time
        $startDateTime = new DateTime($scheduleDate . ' ' . $startTime);
        $endDateTime = new DateTime($scheduleDate . ' ' . $endTime);
        
        // Add 1 day to end time for overnight shifts
        if ($shiftType === 'overnight') {
            $endDateTime->modify('+1 day');
        } 
        // Also handle if end time is earlier than start time (crossing midnight)
        elseif (strtotime($endTime) <= strtotime($startTime)) {
            $endDateTime->modify('+1 day');
        }
        
        // Calculate difference in seconds
        $interval = $startDateTime->diff($endDateTime);
        $seconds = ($interval->days * 24 * 3600) + 
                ($interval->h * 3600) + 
                ($interval->i * 60) + 
                $interval->s;
        
        return $seconds;
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