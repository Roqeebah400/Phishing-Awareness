<?php
// signup.php — User Registration
require_once __DIR__ . '/db.php';
session_start();

$error = '';
$success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $name             = trim($_POST['name'] ?? '');
    $email            = trim($_POST['email'] ?? '');
    $password         = $_POST['password'] ?? '';
    $confirm_password = $_POST['confirm_password'] ?? '';

    if ($name === '' || $email === '' || $password === '') {
        $error = 'All fields are required.';
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $error = 'Please enter a valid email address.';
    } elseif (strlen($password) < 6) {
        $error = 'Password must be at least 6 characters.';
    } elseif ($password !== $confirm_password) {
        $error = 'Passwords do not match.';
    } else {
        try {
            $stmt = $pdo->prepare("SELECT id FROM users WHERE email = :email LIMIT 1");
            $stmt->execute([':email' => $email]);

            if ($stmt->fetch()) {
                $error = 'An account with this email already exists.';
            } else {
                $hash = password_hash($password, PASSWORD_DEFAULT);
                $stmt = $pdo->prepare("INSERT INTO users (name, email, password_hash, role) VALUES (:name, :email, :hash, 'user')");
                $stmt->execute([':name' => $name, ':email' => $email, ':hash' => $hash]);

                $success = 'Account created successfully! You can now log in.';
            }
        } catch (PDOException $e) {
            $error = 'Database error during registration.';
        }
    }
}
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>PhishShield — Create Account</title>
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
      <h1>Build the instincts that stop a real attack.</h1>
      <p>Create your account to run email checks whenever something in your inbox looks off, and track how your risk-spotting improves over time.</p>
    </div>
    <div class="ps-auth-foot">&copy; <?= date('Y') ?> PhishShield</div>
  </div>

  <div class="ps-auth-stage">
    <div class="ps-auth-form">
      <h2>Create your account</h2>
      <p class="ps-sub">It only takes a minute to get started.</p>

      <?php if ($error): ?><div class="ps-alert ps-alert-danger"><?= htmlspecialchars($error) ?></div><?php endif; ?>
      <?php if ($success): ?><div class="ps-alert ps-alert-success"><?= htmlspecialchars($success) ?> <a href="login.php">Sign in →</a></div><?php endif; ?>

      <form method="post">
        <div class="ps-field">
          <label class="ps-label" for="name">Full name</label>
          <input type="text" id="name" name="name" class="ps-input" required value="<?= htmlspecialchars($_POST['name'] ?? '') ?>">
        </div>
        <div class="ps-field">
          <label class="ps-label" for="email">Email address</label>
          <input type="email" id="email" name="email" class="ps-input" required value="<?= htmlspecialchars($_POST['email'] ?? '') ?>">
        </div>
        <div class="ps-field">
          <label class="ps-label" for="signupPassword">Password</label>
          <div class="ps-input-group">
            <input type="password" name="password" id="signupPassword" class="ps-input" required>
            <span class="ps-input-suffix" id="toggleSignupPassword"><i class="bi bi-eye" id="signupIcon"></i></span>
          </div>
          <p class="ps-hint">At least 6 characters.</p>
        </div>
        <div class="ps-field">
          <label class="ps-label" for="confirmPassword">Confirm password</label>
          <div class="ps-input-group">
            <input type="password" name="confirm_password" id="confirmPassword" class="ps-input" required>
            <span class="ps-input-suffix" id="toggleConfirmPassword"><i class="bi bi-eye" id="confirmIcon"></i></span>
          </div>
        </div>
        <button type="submit" class="ps-btn ps-btn-primary ps-btn-block">Sign up</button>
      </form>

      <p class="ps-footer-note">Already have an account? <a href="login.php">Sign in</a></p>
    </div>
  </div>
</div>

<script>
  function setupToggle(buttonId, inputId, iconId) {
    document.getElementById(buttonId).addEventListener('click', function () {
      const input = document.getElementById(inputId);
      const icon = document.getElementById(iconId);
      const show = input.type === 'password';
      input.type = show ? 'text' : 'password';
      icon.className = show ? 'bi bi-eye-slash' : 'bi bi-eye';
    });
  }
  setupToggle('toggleSignupPassword', 'signupPassword', 'signupIcon');
  setupToggle('toggleConfirmPassword', 'confirmPassword', 'confirmIcon');
</script>
</body>
</html>