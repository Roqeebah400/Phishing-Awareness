<?php
session_start();

// Destroy all session data
$_SESSION = array();

if (ini_get("session.use_cookies")) {
    $params = session_get_cookie_params();
    setcookie(session_name(), '', time() - 42000,
        $params["path"], $params["domain"],
        $params["secure"], $params["httponly"]
    );
}

session_destroy();
?>
<!DOCTYPE html>
<html>
<head>
    <title>Logged Out</title>
    <style>
        body { font-family: Arial, sans-serif; text-align: center; margin-top: 100px; }
        .box { display: inline-block; padding: 30px 50px; border: 1px solid #ccc; border-radius: 8px; background: #f9f9f9; }
        a { color: #007bff; text-decoration: none; }
    </style>
</head>
<body>
    <div class="box">
        <h2>You have been logged out.</h2>
        <p><a href="admin_login.php">Return to login</a></p>
    </div>
</body>
</html>