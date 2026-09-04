<?php

require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/db.php';

requireAdmin();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: manage.php');
    exit;
}

$user_id = filter_input(
    INPUT_POST,
    'user_id',
    FILTER_VALIDATE_INT
);

if (!$user_id) {
    header('Location: manage.php');
    exit;
}

try {

    // Delete the user's phishing logs first
    $stmt = $pdo->prepare("
        DELETE FROM detector_checks
        WHERE user_id = ?
    ");

    $stmt->execute([$user_id]);


    // Only accounts with role = user, created by THIS admin, can be deleted
    $stmt = $pdo->prepare("
        DELETE FROM users
        WHERE id = ?
        AND role = 'user'
        AND created_by_admin_id = ?
    ");

    $stmt->execute([$user_id, $_SESSION['user_id']]);


    header('Location: manage.php');
    exit;

} catch (PDOException $e) {

    die("Unable to delete user.");

}