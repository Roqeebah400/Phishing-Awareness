<?php
require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/db.php';
requireAdmin();

$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['add_employee'])) {
        $name = trim($_POST['name'] ?? '');
        $email = trim($_POST['email'] ?? '');
        $dept = trim($_POST['department'] ?? 'Unassigned');
        if ($name && filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $stmt = $pdo->prepare("INSERT IGNORE INTO employees (name, email, department) VALUES (:n, :e, :d)");
            $stmt->execute([':n' => $name, ':e' => $email, ':d' => $dept]);
        } else {
            $error = 'Enter a valid name and email.';
        }
    }
        if (isset($_POST['add_campaign'])) {
        $cname = trim($_POST['campaign_name'] ?? '');
        $ctype = $_POST['template_type'] ?? '';
        $allowed_types = ['HR_Memo', 'IT_Support', 'Invoice'];
        if (!in_array($ctype, $allowed_types, true)) {
            $ctype = null; // falls back to the default lesson in training.php
        }
        if ($cname) {
            $stmt = $pdo->prepare("INSERT INTO campaigns (campaign_name, template_type, sent_at) VALUES (:n, :t, NOW())");
            $stmt->execute([':n' => $cname, ':t' => $ctype]);
        }
    }
}

$employees = $pdo->query("SELECT * FROM employees ORDER BY created_at DESC")->fetchAll();
$campaigns = $pdo->query("SELECT * FROM campaigns ORDER BY sent_at DESC")->fetchAll();
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>PhishShield — Employees &amp; Campaigns</title>
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
      <a href="manage.php" class="ps-btn ps-btn-ghost ps-btn-sm">← Back to admin</a>
    </div>
  </div>
</nav>

<div class="ps-shell ps-page">
  <h1 style="font-size:24px;">Employees &amp; campaigns</h1>
  <p style="margin-bottom:24px;">Add simulation targets and define the campaigns you'll send them.</p>

  <?php if ($error): ?><div class="ps-alert ps-alert-danger"><?= htmlspecialchars($error) ?></div><?php endif; ?>

  <div class="ps-grid-2">
    <div>
      <div class="ps-card" style="margin-bottom:20px;">
        <div class="ps-card-body">
          <h3 style="font-size:15px;">Add employee</h3>
          <form method="post">
            <input type="hidden" name="add_employee" value="1">
            <div class="ps-field">
              <input class="ps-input" type="text" name="name" placeholder="Full name" required>
            </div>
            <div class="ps-field">
              <input class="ps-input" type="email" name="email" placeholder="Email" required>
            </div>
            <div class="ps-field">
              <input class="ps-input" type="text" name="department" placeholder="Department">
            </div>
            <button class="ps-btn ps-btn-admin ps-btn-block">Add employee</button>
          </form>
        </div>
      </div>

      <div class="ps-section-head" style="margin-top:0;">
        <h3 style="font-size:15px;">Current employees</h3>
      </div>
      <div class="ps-card">
        <div class="ps-card-body">
          <ul class="ps-row-list">
            <?php if ($employees): ?>
              <?php foreach ($employees as $e): ?>
                <li>
                  <div>
                    <div class="ps-row-title"><?= htmlspecialchars($e['name']) ?></div>
                    <div class="ps-row-sub"><?= htmlspecialchars($e['email']) ?> — <?= htmlspecialchars($e['department']) ?></div>
                  </div>
                  <form action="delete_employee.php" method="POST" onsubmit="return confirm('Are you sure you want to delete this employee?');">
                    <input type="hidden" name="employee_id" value="<?= htmlspecialchars($e['id']) ?>">
                    <button type="submit" class="ps-btn ps-btn-danger ps-btn-sm">Delete</button>
                  </form>
                </li>
              <?php endforeach; ?>
            <?php else: ?>
              <li><span class="ps-row-sub">No employees added yet.</span></li>
            <?php endif; ?>
          </ul>
        </div>
      </div>
    </div>

    <div>
      <div class="ps-card" style="margin-bottom:20px;">
        <div class="ps-card-body">
          <h3 style="font-size:15px;">Add campaign</h3>
          <form method="post">
            <input type="hidden" name="add_campaign" value="1">
            <div class="ps-field">
              <input class="ps-input" type="text" name="campaign_name" placeholder="Campaign name" required>
            </div>
            <div class="ps-field">
              <select class="ps-select" name="template_type" required>
                <option value="" disabled selected>Choose scenario type (controls the training page shown after a click)</option>
                <option value="HR_Memo">HR Memo — fake HR/policy message</option>
                <option value="IT_Support">IT Support — fake account/password alert</option>
                <option value="Invoice">Invoice — fake billing/invoice message</option>
              </select>
            </div>
            <button class="ps-btn ps-btn-admin ps-btn-block">Add campaign</button>
          </form>
        </div>
      </div>

      <div class="ps-section-head" style="margin-top:0;">
        <h3 style="font-size:15px;">Current campaigns</h3>
      </div>
      <div class="ps-card">
        <div class="ps-card-body">
          <ul class="ps-row-list">
            <?php if ($campaigns): ?>
              <?php foreach ($campaigns as $c): ?>
                <li>
                  <div class="ps-row-title"><?= htmlspecialchars($c['campaign_name']) ?></div>
                  <?php if (!empty($c['template_type'])): ?>
                    <span class="ps-badge ps-badge-indigo"><?= htmlspecialchars($c['template_type']) ?></span>
                  <?php else: ?>
                    <span class="ps-badge ps-badge-muted">No scenario set</span>
                  <?php endif; ?>
                </li>
              <?php endforeach; ?>
            <?php else: ?>
              <li><span class="ps-row-sub">No campaigns created yet.</span></li>
            <?php endif; ?>
          </ul>
        </div>
      </div>
    </div>
  </div>

  <a href="send_email.php" class="ps-btn ps-btn-admin" style="margin-top:28px;">Go to send campaign →</a>
</div>
</body>
</html>