<?php
// db.php - Database connection
error_reporting(E_ALL);
$env = getenv('APP_ENV') ?: 'development';
ini_set('display_errors', $env === 'development' ? 1 : 0);

$host    = getenv('DB_HOST') ?: 'localhost';
$db      = getenv('DB_NAME') ?: 'phishing_sim';
$user    = getenv('DB_USER') ?: 'root';
$pass    = getenv('DB_PASS') ?: '';
$charset = 'utf8mb4';

$dsn = "mysql:host=$host;dbname=$db;charset=$charset";

$options = [
     PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
     PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
     PDO::ATTR_EMULATE_PREPARES   => false,
];

try {
     $pdo = new PDO($dsn, $user, $pass, $options);
} catch (\PDOException $e) {
     if ($env === 'development') {
          die("Database connection failed: " . $e->getMessage());
     }
     die("Database connection failed.");
}