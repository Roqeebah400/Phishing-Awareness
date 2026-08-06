<?php
// auth.php — include this at the very top of any page that requires admin login
session_start();

if (empty($_SESSION['admin_id'])) {
    header('Location: login.php');
    exit;
}