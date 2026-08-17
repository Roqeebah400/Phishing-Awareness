<?php
// create_admin.php — RUN ONCE to create your admin account, then DELETE this file
require_once __DIR__ . '/db.php';

$username = 'admin';           // change this if you want
$password = 'roqeebah@2234!';    // change this to your own password before running

$hash = password_hash($password, PASSWORD_DEFAULT);

try {
    $stmt = $pdo->prepare("INSERT INTO admins (username, password_hash) VALUES (:u, :p)");
    $stmt->execute([':u' => $username, ':p' => $hash]);
    echo "Admin account created. Username: $username";
} catch (\Exception $e) {
    echo "Error: " . $e->getMessage();
}