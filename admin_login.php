<?php
// admin_login.php — Admin Login Portal
require_once __DIR__ . '/db.php';

session_start();

if (isset($_SESSION['user_id']) && ($_SESSION['role'] ?? '') === 'admin') {
    header('Location: manage.php');
    exit;
}

$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email    = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';

    if ($email === '' || $password === '') {
        $error = 'Please fill in both email and password.';
    } else {
        try {
            // Find user where role is admin
            $stmt = $pdo->prepare("SELECT id, name, email, password_hash, role FROM users WHERE email = :email AND role = 'admin' LIMIT 1");
            $stmt->execute([':email' => $email]);
            $admin = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($admin && password_verify($password, $admin['password_hash'])) {
                session_regenerate_id(true);

                $_SESSION['user_id']   = $admin['id'];
                $_SESSION['admin_id']  = $admin['id'];
                $_SESSION['user_name'] = $admin['name'];
                $_SESSION['email']     = $admin['email'];
                $_SESSION['role']      = 'admin';

                header('Location: manage.php');
                exit;
            } else {
                $error = 'Invalid admin credentials or non-admin account.';
            }
        } catch (PDOException $e) {
            $error = 'An error occurred during authentication.';
        }
    }
}
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>PhishShield — Admin Login</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-dark">

<div class="container py-5">
    <div class="row justify-content-center">
        <div class="col-md-5">
            <div class="card shadow-sm mt-4 border-danger">
                <div class="card-body p-4">

                    <h3 class="text-center mb-4 text-danger">
                        🔐 Admin Portal Login
                    </h3>

                    <?php if ($error): ?>
                        <div class="alert alert-danger"><?= htmlspecialchars($error) ?></div>
                    <?php endif; ?>

                    <form method="post">
                        <div class="mb-3">
                            <label class="form-label">Admin Email</label>
                            <input type="email" name="email" class="form-control" required value="<?= htmlspecialchars($_POST['email'] ?? '') ?>">
                        </div>

                        <div class="mb-3">
                            <label class="form-label">Password</label>
                            <input type="password" name="password" class="form-control" required>
                        </div>

                        <button type="submit" class="btn btn-danger w-100">Login to Dashboard</button>
                    </form>

                    <div class="text-center mt-3">
                        <small class="text-muted">
                            Need an Admin account? <a href="admin_signup.php" class="text-decoration-none">Sign Up</a>
                        </small>
                    </div>

                </div>
            </div>
        </div>
    </div>
</div>

</body>
</html>