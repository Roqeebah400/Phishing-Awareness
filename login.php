<?php
// login.php — User Login Portal
require_once __DIR__ . '/db.php';
session_start();

if (isset($_SESSION['user_id']) && ($_SESSION['role'] ?? '') === 'user') {
    header('Location: detector.php');
    exit;
}

$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email    = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';

    if ($email === '' || $password === '') {
        $error = 'Please enter email and password.';
    } else {
        try {
            $stmt = $pdo->prepare("SELECT id, name, email, password_hash, role FROM users WHERE email = :email AND role = 'user' LIMIT 1");
            $stmt->execute([':email' => $email]);
            $user = $stmt->fetch();

            if ($user && password_verify($password, $user['password_hash'])) {
                session_regenerate_id(true);
                $_SESSION['user_id']   = $user['id'];
                $_SESSION['user_name'] = $user['name'];
                $_SESSION['role']      = $user['role'];

                header('Location: dashboard.php');
                exit;
            } else {
                $error = 'Invalid email or password.';
            }
        } catch (PDOException $e) {
            $error = 'Authentication error.';
        }
    }
}
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>PhishShield — Sign In</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.5/font/bootstrap-icons.css" rel="stylesheet">
  <link href="assets/phishshield.css" rel="stylesheet">
  <link rel="icon" href="favicon.svg" type="image/svg+xml">
<link rel="alternate icon" href="favicon.ico">
<link rel="apple-touch-icon" href="favicon-180.png">
</head>
<body class="ps-body">

<div class="ps-auth">
  <div class="ps-auth-brand">
    <div class="ps-brand" style="color:#EDEFF5;font-size:18px;">
      <span class="ps-brand-glyph"></span>PhishShield
    </div>
    <div class="ps-auth-copy">
      <h1>Know a phishing email the moment it lands.</h1>
      <p>Sign in to scan suspicious emails, review your risk history, and keep sharpening your instincts.</p>
    </div>
    <div class="ps-auth-foot">&copy; <?= date('Y') ?> PhishShield</div>
  </div>

  <div class="ps-auth-stage">
    <div class="ps-auth-form">
      <h2>Welcome back</h2>
      <p class="ps-sub">Sign in to your PhishShield account.</p>

      <?php if ($error): ?><div class="ps-alert ps-alert-danger"><?= htmlspecialchars($error) ?></div><?php endif; ?>

      <form method="post">
        <div class="ps-field">
          <label class="ps-label" for="email">Email address</label>
          <input type="email" id="email" name="email" class="ps-input" required value="<?= htmlspecialchars($_POST['email'] ?? '') ?>">
        </div>
        <div class="ps-field">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">
            <label class="ps-label" for="loginPassword" style="margin-bottom:0;">Password</label>
            <a href="forgot_password.php" class="ps-small">Forgot password?</a>
          </div>
          <div class="ps-input-group">
            <input type="password" name="password" id="loginPassword" class="ps-input" required>
            <span class="ps-input-suffix" id="toggleLoginPassword"><i class="bi bi-eye" id="loginIcon"></i></span>
          </div>
        </div>
        <button type="submit" class="ps-btn ps-btn-primary ps-btn-block">Sign in</button>
      </form>

      <p class="ps-footer-note">Need an account? <a href="signup.php">Sign up</a></p>
      <p class="ps-footer-note">Administrator? <a href="admin_login.php">Go to admin login</a></p>
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