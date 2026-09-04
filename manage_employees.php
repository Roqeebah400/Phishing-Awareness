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
  <title>PhishShield — Manage Employees & Campaigns</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">
<nav class="navbar navbar-dark bg-danger px-4">
  <span class="navbar-brand">⚙️ Employees & Campaigns</span>
  <a href="manage.php" class="btn btn-dark btn-sm">Back to Admin</a>
</nav>
<div class="container py-5">
  <?php if ($error): ?><div class="alert alert-danger"><?= htmlspecialchars($error) ?></div><?php endif; ?>

  <div class="row">
    <div class="col-md-6">
      <h4>Add Employee</h4>
      <form method="post" class="card card-body mb-4">
        <input type="hidden" name="add_employee" value="1">
        <input class="form-control mb-2" type="text" name="name" placeholder="Full name" required>
        <input class="form-control mb-2" type="email" name="email" placeholder="Email" required>
        <input class="form-control mb-2" type="text" name="department" placeholder="Department">
        <button class="btn btn-primary">Add Employee</button>
      </form>
      <h5>Current Employees</h5>
      <ul class="list-group mb-4">
        <?php foreach ($employees as $e): ?>
          <li class="list-group-item d-flex justify-content-between align-items-center">
            <span><?= htmlspecialchars($e['name']) ?> — <?= htmlspecialchars($e['email']) ?> (<?= htmlspecialchars($e['department']) ?>)</span>
            <form action="delete_employee.php" method="POST" style="display:inline;" onsubmit="return confirm('Are you sure you want to delete this employee?');">
              <input type="hidden" name="employee_id" value="<?= htmlspecialchars($e['id']) ?>">
              <button type="submit" class="btn btn-danger btn-sm">🗑️ Delete</button>
            </form>
          </li>
        <?php endforeach; ?>
      </ul>
    </div>

    <div class="col-md-6">
      <h4>Add Campaign</h4>
      <form method="post" class="card card-body mb-4">
        <input type="hidden" name="add_campaign" value="1">
        <input class="form-control mb-2" type="text" name="campaign_name" placeholder="Campaign name" required>
        <select class="form-select mb-2" name="template_type" required>
          <option value="" disabled selected>Choose scenario type (controls the training page shown after a click)</option>
          <option value="HR_Memo">HR Memo — fake HR/policy message</option>
          <option value="IT_Support">IT Support — fake account/password alert</option>
          <option value="Invoice">Invoice — fake billing/invoice message</option>
        </select>
        <button class="btn btn-primary">Add Campaign</button>
      </form>
      <h5>Current Campaigns</h5>
      <ul class="list-group">
                <?php foreach ($campaigns as $c): ?>
          <li class="list-group-item">
            <?= htmlspecialchars($c['campaign_name']) ?>
            <?php if (!empty($c['template_type'])): ?>
              <span class="badge bg-secondary ms-1"><?= htmlspecialchars($c['template_type']) ?></span>
            <?php else: ?>
              <span class="badge bg-light text-muted ms-1">no scenario set</span>
            <?php endif; ?>
          </li>
        <?php endforeach; ?>
      </ul>
    </div>
  </div>

  <a href="send_email.php" class="btn btn-danger mt-3">Go to Send Campaign →</a>
</div>
</body>
</html>