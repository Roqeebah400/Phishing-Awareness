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
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>PhishShield — Email Sending Settings</title>
  <link href="assets/phishshield.css" rel="stylesheet">
</head>
<body class="ps-body">

<nav class="ps-nav is-admin">
  <div class="ps-nav-inner">
    <div class="ps-brand"><span class="ps-brand-glyph"></span>PhishShield <span class="ps-mode-tag">Admin</span></div>
    <div class="ps-nav-actions">
      <a href="manage.php" class="ps-btn ps-btn-ghost ps-btn-sm">← Back to admin</a>
    </div>
  </div>
</nav>

<div class="ps-shell-narrow ps-page">
  <div style="max-width:520px;margin:0 auto;">
    <h1 style="font-size:24px;">Email sending settings</h1>
    <p style="margin-bottom:20px;">Configure the account campaign emails are sent from.</p>

    <?php if ($error): ?><div class="ps-alert ps-alert-danger"><?= htmlspecialchars($error) ?></div><?php endif; ?>
    <?php if ($success): ?><div class="ps-alert ps-alert-success"><?= htmlspecialchars($success) ?></div><?php endif; ?>

    <div class="ps-card">
      <div class="ps-card-body">
        <p class="ps-small" style="margin-bottom:20px;">Emails are sent via <a href="https://www.brevo.com" target="_blank">Brevo</a>. Create your own free Brevo account, verify your sending domain there, then paste your API key below.</p>
        <form method="post">
          <div class="ps-field">
            <label class="ps-label">Brevo API key</label>
            <input type="password" name="brevo_api_key" class="ps-input" placeholder="xkeysib-..." value="<?= htmlspecialchars($settings['brevo_api_key'] ?? '') ?>" required>
            <p class="ps-hint">Find this in your Brevo account under Settings → SMTP &amp; API → API Keys.</p>
          </div>
          <div class="ps-field">
            <label class="ps-label">From email</label>
            <input type="email" name="from_email" class="ps-input" placeholder="e.g. security@yourcompany.com" value="<?= htmlspecialchars($settings['from_email'] ?? '') ?>" required>
            <p class="ps-hint">Must be an address on a domain you've verified in Brevo.</p>
          </div>
          <div class="ps-field">
            <label class="ps-label">From name</label>
            <input type="text" name="from_name" class="ps-input" placeholder="e.g. IT Support" value="<?= htmlspecialchars($settings['from_name'] ?? 'IT Support') ?>">
          </div>
          <button type="submit" class="ps-btn ps-btn-admin ps-btn-block">Save settings</button>
        </form>
      </div>
    </div>
  </div>
</div>
</body>
</html>