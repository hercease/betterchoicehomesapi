<?php
use PHPMailer\PHPMailer\PHPMailer; 
use PHPMailer\PHPMailer\Exception as PHPMailerException;
class allModels {
    private $db;

    public function __construct($db){
		$this->db = $db;
    }

    public function sanitizeInput($data) {
        if (is_array($data)) {
            // Loop through each element of the array and sanitize recursively
            foreach ($data as $key => $value) {
                $data[$key] = $this->sanitizeInput($value);
            }
        } else {
            // If it's not an array, sanitize the string
            $data = trim($data); // Remove unnecessary spaces
            $data = stripslashes($data); // Remove backslashes
            $data = htmlspecialchars($data); // Convert special characters to HTML entities
        }
        return $data;
    }

    function generateRandomPassword($length = 10): string {

        $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
        $password = '';
        $maxIndex = strlen($chars) - 1;

        for ($i = 0; $i < $length; $i++) {
            $password .= $chars[random_int(0, $maxIndex)];
        }

        return $password;

    }

    public function random_string($length){
		return substr(bin2hex(random_bytes($length)), 0, $length);
	}

	public function encryptCookie($value){

		$byte = $this->random_string(20);
		$key = hex2bin($byte);

		$cipher = "AES-256-CBC";
		$ivlen = openssl_cipher_iv_length($cipher);
		$iv = openssl_random_pseudo_bytes($ivlen);

		$ciphertext = openssl_encrypt($value, $cipher, $key, 0, $iv);

		return( base64_encode($ciphertext . '::' . $iv. '::' .$key) );
	}

	// Decrypt cookie
	function decryptCookie( $ciphertext ){
		$cipher = "AES-256-CBC";
		list($encrypted_data, $iv,$key) = explode('::', base64_decode($ciphertext));
		return openssl_decrypt($encrypted_data, $cipher, $key, 0, $iv);
	}

    public function getUserInfo($emailOrId){

        if (empty($emailOrId)) {
            return null;
        }

        $isId = is_numeric($emailOrId);
        $userQuery = "
            SELECT 
                u.id AS user_id, u.firstname, u.lastname, u.password, u.email, u.location, 
                u.role, u.isActive, u.reg_date, u.isAdmin, 
                ud.driver_license_expiry_date, ud.address, ud.dob, ud.sin, ud.contact_number, ud.driver_license_number,
                ud.transit_number, ud.institution_number, ud.account_number, ud.province, ud.postal_code, ud.city
            FROM users u
            LEFT JOIN user_details ud ON u.id = ud.user_id
            WHERE " . ($isId ? "u.id = ?" : "u.email = ?");
        
        $stmt = $this->db->prepare($userQuery);
        $isId ? $stmt->bind_param("i", $emailOrId) : $stmt->bind_param("s", $emailOrId);
        $stmt->execute();
        $result = $stmt->get_result();
        $user = $result->fetch_assoc();
        $stmt->close();

        if (!$user) {
            return null; // User not found
        }

        // Fetch documents separately
        $docStmt = $this->db->prepare("SELECT dt.id, dt.name AS title, dt.tag AS doc_tag, dt.is_required, d.name AS document_name, d.isApproved
            FROM document_types dt LEFT JOIN documents d ON d.doc_tag = dt.tag AND d.user_id = ?
        ");
        $docStmt->bind_param("i", $user['user_id']);
        $docStmt->execute();
        $docResult = $docStmt->get_result();
        $documents = [];
        while ($doc = $docResult->fetch_assoc()) {
            $fileUrl = '';
            if (!empty($doc['document_name'])) {
                $fileUrl = (defined('IMAGE_URL') ? IMAGE_URL : '') . "/public/assets/img/" . $doc['document_name'];
            }
            $documents[] = [
                'id'         => $doc['id'],
                'title'      => $doc['title'],
                'tag'        => $doc['doc_tag'],
                'file_name'  => $doc['document_name'],
                'file_url'   => $fileUrl,
                'isApproved' => (bool)$doc['isApproved'],
                'optional'   => (bool)$doc['is_required'],
            ];
        }
        $docStmt->close();

        // Fetch certificates separately
        $certStmt = $this->db->prepare("
            SELECT id, certificate_name, isApproved, cert_tag, title 
            FROM certificates 
            WHERE user_id = ?
            ORDER BY id ASC
        ");
        $certStmt->bind_param("i", $user['user_id']);
        $certStmt->execute();
        $certResult = $certStmt->get_result();
        $certificates = [];
        while ($cert = $certResult->fetch_assoc()) {
            $certFileUrl = '';
            if (!empty($cert['certificate_name'])) {
                $certFileUrl = (defined('IMAGE_URL') ? IMAGE_URL : '') . "/public/assets/img/" . $cert['certificate_name'];
            }
            $certificates[] = [
                'id'         => $cert['id'],
                'cert_tag'   => $cert['cert_tag'],
                'title'      => $cert['title'],
                'file_name'  => $cert['certificate_name'],
                'file_url'   => $certFileUrl,
                'isApproved' => (bool)$cert['isApproved'],
                'optional'   => true,
            ];
        }
        $certStmt->close();

         // Fetch stats for the current month
        $statStmt = $this->db->prepare("
            SELECT id, schedule_date, clockin, clockout, pay_per_hour, shift_type
            FROM scheduling
            WHERE user_id = ? 
            AND MONTH(schedule_date) = MONTH(CURRENT_DATE())
            AND YEAR(schedule_date) = YEAR(CURRENT_DATE())
        ");
        $statStmt->bind_param("i", $user['user_id']);
        $statStmt->execute();
        $statResult = $statStmt->get_result();

        $records = [];
        $totalHours = 0;
        $totalPay = 0;
        $daysAttended = [];

        while ($stat = $statResult->fetch_assoc()) {
            $records[] = $stat;

            if (!empty($stat['clockin']) && !empty($stat['clockout'])) {

                $startDateTime = new DateTime($stat['schedule_date'] . ' ' . $stat['clockin']);
        
                // Create end datetime - add 1 day for overnight shifts
                $endDateTime = new DateTime($stat['schedule_date'] . ' ' . $stat['clockout']);
                if ($stat['shift_type'] === 'overnight') {
                    $endDateTime->modify('+24 hours');
                }
                
                // Calculate difference in hours
                $interval = $startDateTime->diff($endDateTime);
                $hours = $interval->h + ($interval->i / 60) + ($interval->s / 3600);

                /*$start = strtotime($stat['schedule_date'] . ' ' . $stat['clockin']);
                $end   = strtotime($stat['schedule_date'] . ' ' . $stat['clockout']);
                
                // For overnight shifts, check if clockout is earlier than clockin
                if ($stat['shift_type'] === 'overnight') {
                    $end = strtotime('+1 day', $end);
                }
                
                $hours = ($end - $start) / 3600;*/

                if ($hours > 0) {
                    $totalHours += $hours;
                    $totalPay += $hours * (float)$stat['pay_per_hour'];
                    $daysAttended[$stat['schedule_date']] = true;
                }
            }
        }
        $statStmt->close();

        $summary = [
            'total_hours'        => round($totalHours, 2),
            'total_days_attended'=> count($daysAttended),
            'total_expected_pay' => round($totalPay, 2),
            'total_schedules'    => count($records),
        ];

        //fetch user activities
        $activitiesStmt = $this->db->prepare("SELECT action, description, date FROM activities WHERE user_id = ?");
        $activitiesStmt->bind_param("i", $user['user_id']);
        $activitiesStmt->execute();
        $activitiesResult = $activitiesStmt->get_result();
        $activities = [];
        while ($act = $activitiesResult->fetch_assoc()) {
            $activities[] = [
                'action' => $act['action'],
                'date'   => date("F j, Y, g:i A", strtotime($act['date']))
            ];
        }

        // Attach to user
        $user['documents']      = $documents;
        $user['certifications'] = $certificates;
        $user['stats']          = $summary;
        $user['activities']     = $activities;

        return $user;
    }

    public function sendmail($email,$name,$body,$subject){

        require_once 'PHPMailer/src/Exception.php';
        require_once 'PHPMailer/src/PHPMailer.php';
        require_once 'PHPMailer/src/SMTP.php';

        $mail = new PHPMailer(true);
        
        try {
            
            $mail->isSMTP();                           
            $mail->Host       = SMTP_HOST;      
            $mail->SMTPAuth   = true;
            $mail->SMTPKeepAlive = true; //SMTP connection will not close after each email sent, reduces SMTP overhead	
            $mail->Username   = SMTP_USERNAME;    
            $mail->Password   = SMTP_PASSWORD;             
            $mail->SMTPSecure = PHPMailer::ENCRYPTION_SMTPS;   
            $mail->Port       = 465;               
    
            //Recipients
            $mail->setFrom(SMTP_FROM_EMAIL, 'Better Choice Homes'); // Sender's email and name
            $mail->addAddress("$email", "$name"); 
            
            $mail->isHTML(true); 
            $mail->Subject = $subject;
            $mail->Body    = $body;
    
            $mail->send();
            $mail->clearAddresses();
            //return true;
            
        } catch (Exception $e){
            return "Message could not be sent. Mailer Error: {$mail->ErrorInfo}";
        }
    }

    public function sendPush($to, $title, $body) {
        $data = [
            "to" => $to,
            "sound" => "default",
            "title" => $title,
            "body" => $body,
        ];

        $ch = curl_init("https://exp.host/--/api/v2/push/send");
        curl_setopt($ch, CURLOPT_HTTPHEADER, ["Content-Type: application/json"]);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
        $response = curl_exec($ch);
        curl_close($ch);

        return $response;
    }

// Example usage:
//$token = "ExponentPushToken[xxxxxxxxxxxxxxxxxxxxxx]";
//echo sendPush($token, "Hello!", "This is a test notification.");


    public function uploadDocumentImage($userId, $tag, $fileInputName) {
        // 1. Define upload directory
        $uploadDir = UPLOAD_URL;

        // Ensure directory exists
        if (!file_exists($uploadDir)) {
            mkdir($uploadDir, 0777, true);
        }

        // 2. Validate file upload
        if (!isset($_FILES[$fileInputName]) || $_FILES[$fileInputName]['error'] !== UPLOAD_ERR_OK) {
            return ['status' => false, 'message' => 'No file uploaded or upload error'];
        }

        $fileTmpPath = $_FILES[$fileInputName]['tmp_name'];
        $fileName = basename($_FILES[$fileInputName]['name']);
        $fileExtension = strtolower(pathinfo($fileName, PATHINFO_EXTENSION));

        // 3. Allowed extensions
        $allowedExt = ['pdf'];
        if (!in_array($fileExtension, $allowedExt)) {
            return ['status' => false, 'message' => 'Invalid file type'];
        }

        // 4. Create unique file name
        $newFileName = uniqid("doc_") . "." . $fileExtension;
        $destPath = $uploadDir . $newFileName;

        // 5. Move file
        if (!move_uploaded_file($fileTmpPath, $destPath)) {
            return ['status' => false, 'message' => 'Error saving file'];
        }

        // 6. Save file name in database for the given tag
        $stmt = $this->db->prepare("UPDATE documents SET name = ? WHERE user_id = ? AND tag = ?");
        $stmt->bind_param("sis", $newFileName, $userId, $tag);
        if ($stmt->execute()) {
            return ['status' => true, 'message' => 'File uploaded successfully', 'file_name' => $newFileName];
        } else {
            return ['status' => false, 'message' => 'Database update failed'];
        }
    }

    public function getTodayAppointmentLocation($email, $userLng, $userLat, $isClockedIn = false) {

        $today = date('Y-m-d'); // Current date
    
        $sql = "
            SELECT 
                a.id AS appointment_id,
                a.latitude,
                a.longitude,
                a.appointment_date,
                ST_Distance_Sphere(
                    POINT(a.longitude, a.latitude),
                    POINT(?, ?)
                ) AS distance
            FROM appointments a
            INNER JOIN users u ON a.user_id = u.id
            WHERE u.email = ?
            AND DATE(a.appointment_date) = ?
            LIMIT 1
        ";

        $stmt = $this->db->prepare($sql);
        $stmt->bind_param("ddss", $userLng, $userLat, $email, $today);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows === 0) {
            echo json_encode(['status' => 'no_appointment']);
            exit;
        }
    
        $row = $result->fetch_assoc();

            $response =  [
                "id"        => $row['appointment_id'],
                "latitude"  => $row['latitude'],
                "longitude" => $row['longitude'],
                "distance"  => $row['distance'],
                "date"      => $row['appointment_date'],
                "action"    => null
            ];

            if ($row['distance'] <= 5) {
                $response["action"] = "notify_login";
            } elseif ($isClockedIn && $row['distance'] > 5 && $row['distance'] <= 10) {
                $response["action"] = "warn_far";
            } elseif ($isClockedIn && $row['distance'] > 10) {
                $response["action"] = "auto_clock_out";
                // Example auto clock-out update
                $update = $this->db->prepare("UPDATE appointments SET clocked_out = NOW() WHERE id = ?");
                $update->bind_param('i', $row['appointment_id']);
                $update->execute();
            }
    
        return $response; // No appointment today
    }

    public function logActivity($user, $user_id, $action, $description, $date) {
        $stmt = $this->db->prepare("INSERT INTO activities (action, user, user_id, description, date) VALUES (?, ?, ?, ?, ?)");
        $stmt->bind_param("ssiss", $action, $user, $user_id, $description, $date);
        $stmt->execute();
        $stmt->close();
    }

    public function getUserSchedule($email, $schedule_id) {
        $stmt = $this->db->prepare("SELECT * FROM schedules WHERE email = ? AND id = ?");
        $stmt->bind_param("si", $email, $schedule_id);
        $stmt->execute();
        $result = $stmt->get_result();
        return $result->fetch_assoc();
    }
    



}