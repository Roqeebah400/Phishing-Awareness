<?php
// admin_signup.php — Create Admin Account
require_once __DIR__ . '/db.php';

session_start();

$error = '';
$success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $name             = trim($_POST['name'] ?? '');
    $email            = trim($_POST['email'] ?? '');
    $password         = $_POST['password'] ?? '';
    $confirm_password = $_POST['confirm_password'] ?? '';

    if ($name === '') {
        $error = 'Please enter full name.';
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $error = 'Please enter a valid email address.';
    } elseif (strlen($password) < 8) {
        $error = 'Password must be at least 8 characters.';
    } elseif ($password !== $confirm_password) {
        $error = 'Passwords do not match.';
    } else {
        try {
            // Check if email already exists
            $stmt = $pdo->prepare("SELECT id FROM users WHERE email = :email LIMIT 1");
            $stmt->execute([':email' => $email]);

            if ($stmt->fetch()) {
                $error = 'An account with this email already exists.';
            } else {
                $password_hash = password_hash($password, PASSWORD_DEFAULT);

                // Insert into users with admin role
                $stmt = $pdo->prepare("
                    INSERT INTO users (name, email, password_hash, role)
                    VALUES (:name, :email, :password_hash, 'admin')
                ");

                $stmt->execute([
                    ':name'          => $name,
                    ':email'         => $email,
                    ':password_hash' => $password_hash
                ]);

                $success = 'Admin account created successfully! You can now log in.';
            }
        } catch (PDOException $e) {
            // Display exact SQL error during debugging
            $error = 'Database Error: ' . $e->getMessage();
        }
    }
}
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>PhishShield — Admin Signup</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-dark">

<div class="container py-5">
    <div class="row justify-content-center">
        <div class="col-md-5">
            <div class="card shadow-sm mt-4 border-danger">
                <div class="card-body p-4">

                    <h3 class="text-center mb-4 text-danger">
                        ⚙️ Admin Registration
                    </h3>

                    <?php if ($error): ?>
                        <div class="alert alert-danger"><?= htmlspecialchars($error) ?></div>
                    <?php endif; ?>

                    <?php if ($success): ?>
                        <div class="alert alert-success">
                            <?= htmlspecialchars($success) ?>
                            <div class="mt-2">
                                <a href="admin_login.php" class="btn btn-sm btn-danger">Go to Admin Login</a>
                            </div>
                        </div>
                    <?php endif; ?>

                    <form method="post">
                        <div class="mb-3">
                            <label class="form-label">Full Name</label>
                            <input type="text" name="name" class="form-control" required value="<?= htmlspecialchars($_POST['name'] ?? '') ?>">
                        </div>

                        <div class="mb-3">
                            <label class="form-label">Admin Email Address</label>
                            <input type="email" name="email" class="form-control" required value="<?= htmlspecialchars($_POST['email'] ?? '') ?>">
                        </div>

                        <div class="mb-3">
                            <label class="form-label">Password</label>
                            <input type="password" name="password" class="form-control" minlength="8" required>
                        </div>

                        <div class="mb-3">
                            <label class="form-label">Confirm Password</label>
                            <input type="password" name="confirm_password" class="form-control" minlength="8" required>
                        </div>

                        <button type="submit" class="btn btn-danger w-100">Create Admin Account</button>
                    </form>

                    <div class="text-center mt-3">
                        <small class="text-muted">
                            Already an Admin? <a href="admin_login.php" class="text-decoration-none">Login Here</a>
                        </small>
                    </div>

                </div>
            </div>
        </div>
    </div>
</div>

</body>
</html>