<?php

ob_start();

require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/db.php';

requireAdmin();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: manage.php');
    exit;
}

$log_id = filter_input(
    INPUT_POST,
    'log_id',
    FILTER_VALIDATE_INT
);

if (!$log_id) {
    header('Location: manage.php');
    exit;
}

try {

    // Delete the selected phishing log
    $stmt = $pdo->prepare("
        DELETE FROM detector_checks
        WHERE id = ?
    ");

    $stmt->execute([$log_id]);

    // Clear any output before redirecting
    ob_clean();

    // Go back to the admin dashboard
    header('Location: manage.php');
    exit;

} catch (PDOException $e) {

    ob_clean();

    die("Unable to delete phishing log.");

}