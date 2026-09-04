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
    <title>PhishShield — Admin Sign In</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.5/font/bootstrap-icons.css" rel="stylesheet">
    <link href="assets/phishshield.css" rel="stylesheet">
    <link rel="icon" href="favicon.svg" type="image/svg+xml">
<link rel="alternate icon" href="favicon.ico">
<link rel="apple-touch-icon" href="favicon-180.png">
</head>
<body class="ps-body">

<div class="ps-auth">
  <div class="ps-auth-brand is-admin">
    <div class="ps-brand" style="color:#EDEFF5;font-size:18px;">
      <span class="ps-brand-glyph"></span>PhishShield <span class="ps-mode-tag">Admin</span>
    </div>
    <div class="ps-auth-copy">
      <h1>Run your organisation's awareness programme.</h1>
      <p>Manage employees, launch simulation campaigns, and review who needs more training.</p>
    </div>
    <div class="ps-auth-foot">&copy; <?= date('Y') ?> PhishShield</div>
  </div>

  <div class="ps-auth-stage">
    <div class="ps-auth-form">
      <h2>Admin sign in</h2>
      <p class="ps-sub">Restricted to administrator accounts.</p>

      <?php if ($error): ?><div class="ps-alert ps-alert-danger"><?= htmlspecialchars($error) ?></div><?php endif; ?>

      <form method="post">
        <div class="ps-field">
          <label class="ps-label" for="email">Admin email</label>
          <input type="email" id="email" name="email" class="ps-input" required value="<?= htmlspecialchars($_POST['email'] ?? '') ?>">
        </div>
        <div class="ps-field">
          <label class="ps-label" for="loginPassword">Password</label>
          <div class="ps-input-group">
            <input type="password" name="password" id="loginPassword" class="ps-input" required>
            <span class="ps-input-suffix" id="toggleLoginPassword"><i class="bi bi-eye" id="loginIcon"></i></span>
          </div>
        </div>
        <button type="submit" class="ps-btn ps-btn-admin ps-btn-block">Sign in to dashboard</button>
      </form>

      <p class="ps-footer-note">Need an admin account? <a href="admin_signup.php">Sign up</a></p>
      <p class="ps-footer-note">Not an admin? <a href="login.php">Go to user sign in</a></p>
    </div>
  </div>
</div>

<script>
  document.getElementById('toggleLoginPassword').addEventListener('click', function () {
    const input = document.getElementById('loginPassword');
    const icon = document.getElementById('loginIcon');
    const show = input.type === 'password';
    input.type = show ? 'text' : 'password';
    icon.className = show ? 'bi bi-eye-slash' : 'bi bi-eye';
  });
</script>
</body>
</html>