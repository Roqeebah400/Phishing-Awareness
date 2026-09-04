<?php
require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/db.php';
requireAdmin();

$error = '';
$success = '';

// Load existing settings, if any
$settings = $pdo->query("SELECT * FROM smtp_settings ORDER BY id DESC LIMIT 1")->fetch();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $from_email     = trim($_POST['from_email'] ?? '');
    $from_name      = trim($_POST['from_name'] ?? 'IT Support');
    $brevo_api_key  = trim($_POST['brevo_api_key'] ?? '');

    // Legacy columns from the SMTP era are still NOT NULL in the DB — Brevo doesn't
    // need them, so we just fill placeholders. Safe to drop these columns later.
    $smtp_host     = 'n/a-using-brevo-api';
    $smtp_port     = 0;
    $smtp_username = 'n/a-using-brevo-api';
    $smtp_password = 'n/a-using-brevo-api';

    if (!filter_var($from_email, FILTER_VALIDATE_EMAIL)) {
        $error = 'Please enter a valid From Email address.';
    } elseif ($brevo_api_key === '') {
        $error = 'Please enter your Brevo API key.';
    } else {
        try {
            if ($settings) {
                // Update the existing row
                $stmt = $pdo->prepare(
                    "UPDATE smtp_settings SET smtp_host=:host, smtp_port=:port, smtp_username=:user, smtp_password=:pass, from_email=:femail, from_name=:fname, brevo_api_key=:bkey WHERE id=:id"
                );
                $stmt->execute([
                    ':host' => $smtp_host, ':port' => $smtp_port, ':user' => $smtp_username,
                    ':pass' => $smtp_password, ':femail' => $from_email, ':fname' => $from_name,
                    ':bkey' => $brevo_api_key, ':id' => $settings['id']
                ]);
            } else {
                // First time saving settings
                $stmt = $pdo->prepare(
                    "INSERT INTO smtp_settings (smtp_host, smtp_port, smtp_username, smtp_password, from_email, from_name, brevo_api_key) VALUES (:host, :port, :user, :pass, :femail, :fname, :bkey)"
                );
                $stmt->execute([
                    ':host' => $smtp_host, ':port' => $smtp_port, ':user' => $smtp_username,
                    ':pass' => $smtp_password, ':femail' => $from_email, ':fname' => $from_name,
                    ':bkey' => $brevo_api_key
                ]);
            }
            $success = 'Sender settings saved successfully.';
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
          <p class="text-muted">Emails are sent via <a href="https://www.brevo.com" target="_blank">Brevo</a>. Create your own free Brevo account, verify your sending domain there, then paste your API key below.</p>
          <form method="post">
            <div class="mb-3">
              <label class="form-label">Brevo API Key</label>
              <input type="password" name="brevo_api_key" class="form-control" placeholder="xkeysib-..." value="<?= htmlspecialchars($settings['brevo_api_key'] ?? '') ?>" required>
              <small class="text-muted">Find this in your Brevo account under Settings → SMTP & API → API Keys.</small>
            </div>
            <div class="mb-3">
              <label class="form-label">From Email</label>
              <input type="email" name="from_email" class="form-control" placeholder="e.g. security@yourcompany.com" value="<?= htmlspecialchars($settings['from_email'] ?? '') ?>" required>
              <small class="text-muted">Must be an address on a domain you've verified in Brevo.</small>
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