<?php
require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/db.php';
requireAdmin();

$error = '';
$success = '';

// Load existing settings, if any
$settings = $pdo->query("SELECT * FROM smtp_settings ORDER BY id DESC LIMIT 1")->fetch();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $smtp_host     = trim($_POST['smtp_host'] ?? '');
    $smtp_port     = filter_input(INPUT_POST, 'smtp_port', FILTER_VALIDATE_INT);
    $smtp_username = trim($_POST['smtp_username'] ?? '');
    $smtp_password = trim($_POST['smtp_password'] ?? '');
    $from_email    = trim($_POST['from_email'] ?? '');
    $from_name     = trim($_POST['from_name'] ?? 'IT Support');

    if (!$smtp_host || !$smtp_port || !$smtp_username || !$smtp_password || !filter_var($from_email, FILTER_VALIDATE_EMAIL)) {
        $error = 'Please fill in all fields correctly (from email must be a valid email address).';
    } else {
        try {
            if ($settings) {
                // Update the existing row
                $stmt = $pdo->prepare(
                    "UPDATE smtp_settings SET smtp_host=:host, smtp_port=:port, smtp_username=:user, smtp_password=:pass, from_email=:femail, from_name=:fname WHERE id=:id"
                );
                $stmt->execute([
                    ':host' => $smtp_host, ':port' => $smtp_port, ':user' => $smtp_username,
                    ':pass' => $smtp_password, ':femail' => $from_email, ':fname' => $from_name,
                    ':id' => $settings['id']
                ]);
            } else {
                // First time saving settings
                $stmt = $pdo->prepare(
                    "INSERT INTO smtp_settings (smtp_host, smtp_port, smtp_username, smtp_password, from_email, from_name) VALUES (:host, :port, :user, :pass, :femail, :fname)"
                );
                $stmt->execute([
                    ':host' => $smtp_host, ':port' => $smtp_port, ':user' => $smtp_username,
                    ':pass' => $smtp_password, ':femail' => $from_email, ':fname' => $from_name
                ]);
            }
            $success = 'SMTP settings saved successfully.';
            $settings = $pdo->query("SELECT * FROM smtp_settings ORDER BY id DESC LIMIT 1")->fetch();
        } catch (PDOException $e) {
            $error = 'Database error while saving settings.';
        }
    }
}
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>PhishShield — Email Sending Settings</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">
<nav class="navbar navbar-dark bg-danger px-4">
  <span class="navbar-brand">⚙️ Email Sending Settings</span>
  <a href="manage.php" class="btn btn-dark btn-sm">Back to Admin</a>
</nav>
<div class="container py-5">
  <div class="row justify-content-center">
    <div class="col-md-7">

      <?php if ($error): ?><div class="alert alert-danger"><?= htmlspecialchars($error) ?></div><?php endif; ?>
      <?php if ($success): ?><div class="alert alert-success"><?= htmlspecialchars($success) ?></div><?php endif; ?>

      <div class="card shadow-sm">
        <div class="card-body">
          <p class="text-muted">Connect your own email sending account here. Get these details from your email provider (Mailtrap, SendGrid, Gmail SMTP, Microsoft 365, etc).</p>
          <form method="post">
            <div class="mb-3">
              <label class="form-label">SMTP Host</label>
              <input type="text" name="smtp_host" class="form-control" placeholder="e.g. sandbox.smtp.mailtrap.io" value="<?= htmlspecialchars($settings['smtp_host'] ?? '') ?>" required>
            </div>
            <div class="mb-3">
              <label class="form-label">SMTP Port</label>
              <input type="number" name="smtp_port" class="form-control" placeholder="e.g. 2525 or 587" value="<?= htmlspecialchars($settings['smtp_port'] ?? '587') ?>" required>
            </div>
            <div class="mb-3">
              <label class="form-label">SMTP Username</label>
              <input type="text" name="smtp_username" class="form-control" value="<?= htmlspecialchars($settings['smtp_username'] ?? '') ?>" required>
            </div>
            <div class="mb-3">
              <label class="form-label">SMTP Password</label>
              <input type="password" name="smtp_password" class="form-control" value="<?= htmlspecialchars($settings['smtp_password'] ?? '') ?>" required>
            </div>
            <div class="mb-3">
              <label class="form-label">From Email</label>
              <input type="email" name="from_email" class="form-control" placeholder="e.g. security@yourcompany.com" value="<?= htmlspecialchars($settings['from_email'] ?? '') ?>" required>
            </div>
            <div class="mb-3">
              <label class="form-label">From Name</label>
              <input type="text" name="from_name" class="form-control" placeholder="e.g. IT Support" value="<?= htmlspecialchars($settings['from_name'] ?? 'IT Support') ?>">
            </div>
            <button type="submit" class="btn btn-danger">Save Settings</button>
          </form>
        </div>
      </div>

    </div>
  </div>
</div>
</body>
</html>