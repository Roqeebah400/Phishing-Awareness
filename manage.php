<?php
// manage.php — Admin Overview

require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/db.php';

requireAdmin();

$admin_id = $_SESSION['user_id'];

$error = '';
$success = '';

// Admin creating a new user account directly
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['create_user'])) {
    $new_name     = trim($_POST['new_name'] ?? '');
    $new_email    = trim($_POST['new_email'] ?? '');
    $new_password = $_POST['new_password'] ?? '';

    if ($new_name === '' || !filter_var($new_email, FILTER_VALIDATE_EMAIL)) {
        $error = 'Please enter a valid name and email.';
    } elseif (strlen($new_password) < 6) {
        $error = 'Password must be at least 6 characters.';
    } else {
        $stmt = $pdo->prepare("SELECT id FROM users WHERE email = :email LIMIT 1");
        $stmt->execute([':email' => $new_email]);
        if ($stmt->fetch()) {
            $error = 'An account with this email already exists.';
        } else {
            $hash = password_hash($new_password, PASSWORD_DEFAULT);
            $stmt = $pdo->prepare(
                "INSERT INTO users (name, email, password_hash, role, created_by_admin_id) VALUES (:n, :e, :h, 'user', :aid)"
            );
            $stmt->execute([':n' => $new_name, ':e' => $new_email, ':h' => $hash, ':aid' => $admin_id]);
            $success = "Account created for {$new_name}. Share their email and password with them so they can log in.";
        }
    }
}

$total_users   = $pdo->prepare("SELECT COUNT(*) FROM users WHERE role = 'user' AND created_by_admin_id = :aid");
$total_users->execute([':aid' => $admin_id]);
$total_users = $total_users->fetchColumn();

$total_scans = $pdo->prepare(
    "SELECT COUNT(*) FROM detector_checks dc JOIN users u ON dc.user_id = u.id WHERE u.created_by_admin_id = :aid"
);
$total_scans->execute([':aid' => $admin_id]);
$total_scans = $total_scans->fetchColumn();

$total_threats = $pdo->prepare(
    "SELECT COUNT(*) FROM detector_checks dc JOIN users u ON dc.user_id = u.id WHERE u.created_by_admin_id = :aid AND dc.verdict LIKE '%High%'"
);
$total_threats->execute([':aid' => $admin_id]);
$total_threats = $total_threats->fetchColumn();

$users_stmt = $pdo->prepare(
    "SELECT id, name, email, department, created_at FROM users WHERE role = 'user' AND created_by_admin_id = :aid ORDER BY created_at DESC"
);
$users_stmt->execute([':aid' => $admin_id]);
$users = $users_stmt->fetchAll();

$all_campaigns = $pdo->query("SELECT id, campaign_name FROM campaigns ORDER BY campaign_name")->fetchAll();
$selected_campaign = filter_input(INPUT_GET, 'campaign_id', FILTER_VALIDATE_INT);

if ($selected_campaign) {
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM tracking_logs WHERE action_type = 'sent' AND campaign_id = :cid");
    $stmt->execute([':cid' => $selected_campaign]);
    $sent_count = $stmt->fetchColumn();

    $stmt = $pdo->prepare("SELECT COUNT(*) FROM tracking_logs WHERE action_type = 'clicked' AND campaign_id = :cid");
    $stmt->execute([':cid' => $selected_campaign]);
    $clicked_count = $stmt->fetchColumn();

    $stmt = $pdo->prepare("SELECT COUNT(*) FROM tracking_logs WHERE action_type = 'submitted_data' AND campaign_id = :cid");
    $stmt->execute([':cid' => $selected_campaign]);
    $submitted_count = $stmt->fetchColumn();
} else {
    $sent_count      = $pdo->query("SELECT COUNT(*) FROM tracking_logs WHERE action_type = 'sent'")->fetchColumn();
    $clicked_count   = $pdo->query("SELECT COUNT(*) FROM tracking_logs WHERE action_type = 'clicked'")->fetchColumn();
    $submitted_count = $pdo->query("SELECT COUNT(*) FROM tracking_logs WHERE action_type = 'submitted_data'")->fetchColumn();
}

$click_rate      = $sent_count > 0 ? round(($clicked_count / $sent_count) * 100, 1) : 0;
$compromise_rate = $sent_count > 0 ? round(($submitted_count / $sent_count) * 100, 1) : 0;

$logs_stmt = $pdo->prepare(
    "SELECT dc.*, u.name as user_name, u.email as user_email FROM detector_checks dc
     JOIN users u ON dc.user_id = u.id
     WHERE u.created_by_admin_id = :aid
     ORDER BY dc.created_at DESC"
);
$logs_stmt->execute([':aid' => $admin_id]);
$logs = $logs_stmt->fetchAll();
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>PhishShield — Admin Dashboard</title>
  <link href="assets/phishshield.css" rel="stylesheet">
  <link rel="icon" href="favicon.svg" type="image/svg+xml">
<link rel="alternate icon" href="favicon.ico">
<link rel="apple-touch-icon" href="favicon-180.png">
</head>
<body class="ps-body">

<nav class="ps-nav is-admin">
  <div class="ps-nav-inner">
    <div class="ps-brand"><span class="ps-brand-glyph"></span>PhishShield <span class="ps-mode-tag">Admin</span></div>
    <div class="ps-nav-actions">
      <a href="manage_employees.php" class="ps-btn ps-btn-ghost ps-btn-sm">Employees &amp; campaigns</a>
      <a href="send_email.php" class="ps-btn ps-btn-ghost ps-btn-sm">Send campaign</a>
      <a href="settings.php" class="ps-btn ps-btn-ghost ps-btn-sm">Email settings</a>
      <span class="ps-nav-user">Admin: <strong><?= htmlspecialchars($_SESSION['user_name']) ?></strong></span>
      <a href="logout.php" class="ps-btn ps-btn-admin ps-btn-sm">Logout</a>
    </div>
  </div>
</nav>

<div class="ps-shell ps-page">

  <?php if ($error): ?><div class="ps-alert ps-alert-danger"><?= htmlspecialchars($error) ?></div><?php endif; ?>
  <?php if ($success): ?><div class="ps-alert ps-alert-success"><?= htmlspecialchars($success) ?></div><?php endif; ?>

  <h1 style="font-size:26px;">Admin overview</h1>
  <p style="margin-bottom:20px;">Organisation-wide detector usage and simulation performance.</p>

  <div class="ps-stats">
    <div class="ps-stat accent-blue">
      <div class="ps-stat-label">Total users</div>
      <div class="ps-stat-value"><?= $total_users ?></div>
    </div>
    <div class="ps-stat">
      <div class="ps-stat-label">Total scans</div>
      <div class="ps-stat-value"><?= $total_scans ?></div>
    </div>
    <div class="ps-stat accent-danger">
      <div class="ps-stat-label">Threats detected</div>
      <div class="ps-stat-value"><?= $total_threats ?></div>
    </div>
  </div>

  <div class="ps-section-head" style="margin-top:8px;">
    <h3>Campaign performance</h3>
    <form method="get">
      <select name="campaign_id" class="ps-select" style="width:auto;display:inline-block;" onchange="this.form.submit()">
        <option value="">All campaigns (combined)</option>
        <?php foreach ($all_campaigns as $ac): ?>
          <option value="<?= $ac['id'] ?>" <?= $selected_campaign == $ac['id'] ? 'selected' : '' ?>>
            <?= htmlspecialchars($ac['campaign_name']) ?>
          </option>
        <?php endforeach; ?>
      </select>
    </form>
  </div>

  <div class="ps-stats">
    <div class="ps-stat">
      <div class="ps-stat-label">Emails sent</div>
      <div class="ps-stat-value"><?= $sent_count ?></div>
    </div>
    <div class="ps-stat accent-warn">
      <div class="ps-stat-label">Click rate</div>
      <div class="ps-stat-value"><?= $click_rate ?>%</div>
    </div>
    <div class="ps-stat accent-danger">
      <div class="ps-stat-label">Credential compromise rate</div>
      <div class="ps-stat-value"><?= $compromise_rate ?>%</div>
    </div>
  </div>

  <div class="ps-section-head">
    <h3>Registered users</h3>
    <p>Accounts you've created are only visible on your dashboard.</p>
  </div>

  <div class="ps-card" style="margin-bottom:24px;">
    <div class="ps-card-body">
      <h3 style="font-size:14.5px;">Create a new user account</h3>
      <form method="post" class="ps-grid-2" style="align-items:end;gap:14px;">
        <input type="hidden" name="create_user" value="1">
        <div class="ps-field" style="margin-bottom:0;">
          <label class="ps-label">Full name</label>
          <input type="text" name="new_name" class="ps-input" required>
        </div>
        <div class="ps-field" style="margin-bottom:0;">
          <label class="ps-label">Email</label>
          <input type="email" name="new_email" class="ps-input" required>
        </div>
        <div class="ps-field" style="margin-bottom:0;">
          <label class="ps-label">Password</label>
          <input type="text" name="new_password" class="ps-input" placeholder="min 6 characters" required>
        </div>
        <button type="submit" class="ps-btn ps-btn-admin">Create account</button>
      </form>
      <p class="ps-hint" style="margin-top:12px;">Share the email and password with the person so they can log in at /login.php.</p>
    </div>
  </div>

  <div class="ps-card ps-card-flush" style="margin-bottom:36px;">
    <div class="ps-table-wrap">
      <table class="ps-table">
        <thead>
          <tr><th>ID</th><th>Name</th><th>Email</th><th>Registered</th><th></th></tr>
        </thead>
        <tbody>
          <?php if ($users): ?>
            <?php foreach ($users as $u): ?>
              <tr>
                <td><?= $u['id'] ?></td>
                <td><?= htmlspecialchars($u['name']) ?></td>
                <td><?= htmlspecialchars($u['email']) ?></td>
                <td><?= date('M d, Y', strtotime($u['created_at'])) ?></td>
                <td>
                  <form action="delete_user.php" method="POST" onsubmit="return confirm('Are you sure you want to delete this user?');">
                    <input type="hidden" name="user_id" value="<?= htmlspecialchars($u['id']) ?>">
                    <button type="submit" class="ps-btn ps-btn-danger ps-btn-sm">Delete</button>
                  </form>
                </td>
              </tr>
            <?php endforeach; ?>
          <?php else: ?>
            <tr><td colspan="5"><div class="ps-empty">No users created yet.</div></td></tr>
          <?php endif; ?>
        </tbody>
      </table>
    </div>
  </div>

  <div class="ps-section-head">
    <h3>Phishing detector logs</h3>
  </div>

  <div class="ps-card ps-card-flush">
    <div class="ps-table-wrap">
      <table class="ps-table">
        <thead>
          <tr><th>ID</th><th>User</th><th>Verdict</th><th>Score</th><th>Snippet</th><th>Date</th><th></th></tr>
        </thead>
        <tbody>
          <?php if ($logs): ?>
            <?php foreach ($logs as $l): ?>
              <tr>
                <td><?= $l['id'] ?></td>
                <td><?= htmlspecialchars($l['user_name'] ?? 'Unknown') ?></td>
                <td><span class="ps-badge <?= str_contains($l['verdict'], 'High') ? 'ps-badge-danger' : 'ps-badge-good' ?>"><?= htmlspecialchars($l['verdict']) ?></span></td>
                <td><strong><?= $l['risk_score'] ?>/100</strong></td>
                <td><code><?= htmlspecialchars(substr($l['input_content'], 0, 40)) ?>...</code></td>
                <td><?= date('M d, Y H:i', strtotime($l['created_at'])) ?></td>
                <td>
                  <form action="delete_log.php" method="POST" onsubmit="return confirm('Are you sure you want to delete this phishing log?');">
                    <input type="hidden" name="log_id" value="<?= htmlspecialchars($l['id']) ?>">
                    <button type="submit" class="ps-btn ps-btn-danger ps-btn-sm">Delete</button>
                  </form>
                </td>
              </tr>
            <?php endforeach; ?>
          <?php else: ?>
            <tr><td colspan="7"><div class="ps-empty">No scans logged yet.</div></td></tr>
          <?php endif; ?>
        </tbody>
      </table>
    </div>
  </div>

</div>
</body>
</html>