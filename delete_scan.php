<?php

require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/db.php';

requireUser();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: dashboard.php');
    exit;
}

if (!isset($_POST['scan_id'])) {
    die('Error: Scan ID was not received.');
}

$scan_id = (int) $_POST['scan_id'];

if ($scan_id <= 0) {
    die('Error: Invalid scan ID.');
}

$user_id = (int) $_SESSION['user_id'];

try {

    $stmt = $pdo->prepare("
        DELETE FROM detector_checks
        WHERE id = :id
        AND user_id = :user_id
    ");

    $stmt->execute([
        ':id' => $scan_id,
        ':user_id' => $user_id
    ]);

    if ($stmt->rowCount() === 0) {
        die('Error: This scan could not be deleted.');
    }

    header('Location: dashboard.php');
    exit;

} catch (PDOException $e) {

    die(
        "Database Error: " .
        htmlspecialchars($e->getMessage())
    );
}