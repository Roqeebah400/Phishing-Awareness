<?php

require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/db.php';

requireAdmin();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: manage_employees.php');
    exit;
}

$employee_id = filter_input(
    INPUT_POST,
    'employee_id',
    FILTER_VALIDATE_INT
);

if (!$employee_id) {
    header('Location: manage_employees.php');
    exit;
}

try {

    // tracking_logs.employee_id is ON DELETE SET NULL, so past campaign
    // logs are preserved (just show "Unknown" employee afterward).
    $stmt = $pdo->prepare("
        DELETE FROM employees
        WHERE id = ?
    ");

    $stmt->execute([$employee_id]);

    header('Location: manage_employees.php');
    exit;

} catch (PDOException $e) {

    die("Unable to delete employee.");

}