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
      <h1>Set up the account that runs the programme.</h1>
      <p>Admin accounts can manage employees, dispatch simulation campaigns, and review organisation-wide results.</p>
    </div>
    <div class="ps-auth-foot">&copy; <?= date('Y') ?> PhishShield</div>
  </div>

  <div class="ps-auth-stage">
    <div class="ps-auth-form">
      <h2>Create an admin account</h2>
      <p class="ps-sub">Requires a stronger password than a standard user account.</p>

      <?php if ($error): ?><div class="ps-alert ps-alert-danger"><?= htmlspecialchars($error) ?></div><?php endif; ?>
      <?php if ($success): ?>
        <div class="ps-alert ps-alert-success">
          <?= htmlspecialchars($success) ?>
          <div style="margin-top:8px;"><a href="admin_login.php" class="ps-btn ps-btn-admin ps-btn-sm">Go to admin login</a></div>
        </div>
      <?php endif; ?>

      <form method="post">
        <div class="ps-field">
          <label class="ps-label" for="name">Full name</label>
          <input type="text" id="name" name="name" class="ps-input" required value="<?= htmlspecialchars($_POST['name'] ?? '') ?>">
        </div>
        <div class="ps-field">
          <label class="ps-label" for="email">Admin email address</label>
          <input type="email" id="email" name="email" class="ps-input" required value="<?= htmlspecialchars($_POST['email'] ?? '') ?>">
        </div>
        <div class="ps-field">
          <label class="ps-label" for="adminPassword">Password</label>
          <div class="ps-input-group">
            <input type="password" name="password" id="adminPassword" class="ps-input" minlength="8" required>
            <span class="ps-input-suffix" id="toggleAdminPassword"><i class="bi bi-eye" id="adminPasswordIcon"></i></span>
          </div>
          <p class="ps-hint">At least 8 characters.</p>
        </div>
        <div class="ps-field">
          <label class="ps-label" for="adminConfirmPassword">Confirm password</label>
          <div class="ps-input-group">
            <input type="password" name="confirm_password" id="adminConfirmPassword" class="ps-input" minlength="8" required>
            <span class="ps-input-suffix" id="toggleAdminConfirmPassword"><i class="bi bi-eye" id="adminConfirmIcon"></i></span>
          </div>
        </div>
        <button type="submit" class="ps-btn ps-btn-admin ps-btn-block">Create admin account</button>
      </form>

      <p class="ps-footer-note">Already an admin? <a href="admin_login.php">Log in here</a></p>
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
  setupToggle('toggleAdminPassword', 'adminPassword', 'adminPasswordIcon');
  setupToggle('toggleAdminConfirmPassword', 'adminConfirmPassword', 'adminConfirmIcon');
</script>
</body>
</html>