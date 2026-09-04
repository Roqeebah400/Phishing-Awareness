<?php
// forgot_password.php — Reset User Password
require_once __DIR__ . '/db.php';
session_start();

$error = '';
$success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email            = trim($_POST['email'] ?? '');
    $new_password     = $_POST['new_password'] ?? '';
    $confirm_password = $_POST['confirm_password'] ?? '';

    if ($email === '' || $new_password === '' || $confirm_password === '') {
        $error = 'All fields are required.';
    } elseif (strlen($new_password) < 6) {
        $error = 'Password must be at least 6 characters.';
    } elseif ($new_password !== $confirm_password) {
        $error = 'Passwords do not match.';
    } else {
        try {
            $stmt = $pdo->prepare("SELECT id FROM users WHERE email = :email LIMIT 1");
            $stmt->execute([':email' => $email]);
            $user = $stmt->fetch();

            if ($user) {
                $hash = password_hash($new_password, PASSWORD_DEFAULT);
                $update = $pdo->prepare("UPDATE users SET password_hash = :hash WHERE id = :id");
                $update->execute([':hash' => $hash, ':id' => $user['id']]);

                $success = 'Password updated successfully! You can now log in.';
            } else {
                $error = 'No account found with that email address.';
            }
        } catch (PDOException $e) {
            $error = 'Database error while resetting password.';
        }
    }
}
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>PhishShield — Reset Password</title>
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
      <h1>Locked out happens. Getting back in shouldn't be hard.</h1>
      <p>Confirm your email and choose a new password to regain access to your account.</p>
    </div>
    <div class="ps-auth-foot">&copy; <?= date('Y') ?> PhishShield</div>
  </div>

  <div class="ps-auth-stage">
    <div class="ps-auth-form">
      <h2>Reset your password</h2>
      <p class="ps-sub">Enter your email and a new password below.</p>

      <?php if ($error): ?><div class="ps-alert ps-alert-danger"><?= htmlspecialchars($error) ?></div><?php endif; ?>
      <?php if ($success): ?><div class="ps-alert ps-alert-success"><?= htmlspecialchars($success) ?> <a href="login.php">Sign in →</a></div><?php endif; ?>

      <form method="post">
        <div class="ps-field">
          <label class="ps-label" for="email">Your email address</label>
          <input type="email" id="email" name="email" class="ps-input" required value="<?= htmlspecialchars($_POST['email'] ?? '') ?>">
        </div>
        <div class="ps-field">
          <label class="ps-label" for="newPassword">New password</label>
          <div class="ps-input-group">
            <input type="password" name="new_password" id="newPassword" class="ps-input" required>
            <span class="ps-input-suffix" id="toggleNewPassword"><i class="bi bi-eye" id="newIcon"></i></span>
          </div>
        </div>
        <div class="ps-field">
          <label class="ps-label" for="confirmPassword">Confirm new password</label>
          <div class="ps-input-group">
            <input type="password" name="confirm_password" id="confirmPassword" class="ps-input" required>
            <span class="ps-input-suffix" id="toggleConfirmPassword"><i class="bi bi-eye" id="confirmIcon"></i></span>
          </div>
        </div>
        <button type="submit" class="ps-btn ps-btn-primary ps-btn-block">Update password</button>
      </form>

      <p class="ps-footer-note">Remembered it? <a href="login.php">Back to sign in</a></p>
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
  setupToggle('toggleNewPassword', 'newPassword', 'newIcon');
  setupToggle('toggleConfirmPassword', 'confirmPassword', 'confirmIcon');
</script>
</body>
</html>