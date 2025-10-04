<?php
// Allow from any origin (update for production)
$allowedOrigins = [
    'http://192.168.46.108:8081', // React Native Expo dev
    'https://betterchoicehomesapi.local'
];
$origin = $_SERVER['HTTP_ORIGIN'] ?? '*';

if (in_array($origin, $allowedOrigins)) {
    header("Access-Control-Allow-Origin: $origin");
} else {
    header("Access-Control-Allow-Origin: *"); // For dev; tighten in production
}

header("Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With");
header("Access-Control-Allow-Credentials: true");

// Handle preflight requests
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

require_once('config/config.php');
require_once('controllers/allcontrollers.php');
require_once('controllers/dbcontroller.php');
require_once('models/allmodels.php');
$db = (new Database())->connect();
$controller = new Controllers($db);
$baseDir = '/betterchoicehomesapi';  // Base directory where your app is located
$url = str_replace($baseDir, '', parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH));

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    sendErrorResponse(405, 'Method Not Allowed');
}

try {

    switch ($url){

        case '/login':
            $login = $controller->processLoginMethod();
            sendSuccessResponse($login); // sends as JSON
            break;
        case '/forgot':
            $forgot = $controller->processForgotPassword();
            sendSuccessResponse($forgot); // sends as JSON
            break;
        case '/fetchprofileinfo':
            $profile = $controller->fetchuserDetails();
            sendSuccessResponse($profile); // sends as JSON
            break;
        case '/updateprofile':
            $updateprofile = $controller->updateProfile();
            sendSuccessResponse($updateprofile); // sends as JSON
            break;
        case '/fetchallactivities':
            $allactivities = $controller->fetchAllActivities();
            sendSuccessResponse($allactivities); // sends as JSON
            break;
        case '/changepassword':
            $changepassword = $controller->ChangePassword();
            sendSuccessResponse($changepassword); // sends as JSON
            break;
        case '/fetchschedules':
            $fetchschedule = $controller->fetchSchedules();
            sendSuccessResponse($fetchschedule); // sends as JSON
            break;
        case '/fetchmonthlyschedules':
            $fetchmonthlyschedule = $controller->fetchMonthlySchedules();
            sendSuccessResponse($fetchmonthlyschedule); // sends as JSON
            break;
        case '/attendance':
            $clokinclockout = $controller->Attendance();
            sendSuccessResponse($clokinclockout); // sends as JSON
            break;
        case '/save_notification_token':
            $savenotification = $controller->saveNotification();
            sendSuccessResponse($savenotification); // sends as JSON
            break;
        case '/fingerprintlogin':
            $fingerprintlogin = $controller->processFingerprintLogin();
            sendSuccessResponse($fingerprintlogin); // sends as JSON
            break;
            
    }

}  catch (Exception $e) {
    // Hide sensitive info in production
    sendErrorResponse(500, 'Internal Server Error');
}






function sendSuccessResponse(array $data): void
{
    header('Content-Type: application/json');
    echo json_encode($data);
    exit;
}

/**
 * Send a JSON error response.
 *
 * @param int $statusCode HTTP status code
 * @param string $message Error message
 * @return void
 */
function sendErrorResponse(int $statusCode, string $message): void
{
    http_response_code($statusCode);
    header('Content-Type: application/json');
    echo json_encode($message);
    exit;
}