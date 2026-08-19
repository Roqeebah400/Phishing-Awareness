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
  <title>PhishShield — Reset Password</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.5/font/bootstrap-icons.css" rel="stylesheet">
</head>
<body class="bg-light">
<div class="container py-5">
  <div class="row justify-content-center">
    <div class="col-md-5">
      <div class="card shadow-sm">
        <div class="card-body p-4">
          <h3 class="text-center mb-4 text-primary">🔑 Reset Password</h3>
          <?php if ($error): ?><div class="alert alert-danger"><?= htmlspecialchars($error) ?></div><?php endif; ?>
          <?php if ($success): ?><div class="alert alert-success"><?= htmlspecialchars($success) ?> <a href="login.php">Login</a></div><?php endif; ?>
          <form method="post">
            <div class="mb-3">
              <label class="form-label">Your Email Address</label>
              <input type="email" name="email" class="form-control" required value="<?= htmlspecialchars($_POST['email'] ?? '') ?>">
            </div>
            <div class="mb-3">
              <label class="form-label">New Password</label>
              <div class="input-group">
                <input type="password" name="new_password" id="newPassword" class="form-control" required>
                <button class="btn btn-outline-secondary" type="button" id="toggleNewPassword">
                  <i class="bi bi-eye" id="newIcon"></i>
                </button>
              </div>
            </div>
            <div class="mb-3">
              <label class="form-label">Confirm New Password</label>
              <div class="input-group">
                <input type="password" name="confirm_password" id="confirmPassword" class="form-control" required>
                <button class="btn btn-outline-secondary" type="button" id="toggleConfirmPassword">
                  <i class="bi bi-eye" id="confirmIcon"></i>
                </button>
              </div>
            </div>
            <button type="submit" class="btn btn-primary w-100">Update Password</button>
          </form>
          <div class="text-center mt-3"><small>Remembered it? <a href="login.php">Back to Login</a></small></div>
        </div>
      </div>
    </div>
  </div>
</div>

<script>
  function setupToggle(buttonId, inputId, iconId) {
    document.getElementById(buttonId).addEventListener('click', function () {
      const input = document.getElementById(inputId);
      const icon = document.getElementById(iconId);
      if (input.type === 'password') {
        input.type = 'text';
        icon.classList.remove('bi-eye');
        icon.classList.add('bi-eye-slash');
      } else {
        input.type = 'password';
        icon.classList.remove('bi-eye-slash');
        icon.classList.add('bi-eye');
      }
    });
  }

  setupToggle('toggleNewPassword', 'newPassword', 'newIcon');
  setupToggle('toggleConfirmPassword', 'confirmPassword', 'confirmIcon');
</script>
</body>
</html>