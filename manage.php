<?php
// manage.php — Admin Overview
require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/db.php';

requireAdmin();

$total_users   = $pdo->query("SELECT COUNT(*) FROM users WHERE role = 'user'")->fetchColumn();
$total_scans   = $pdo->query("SELECT COUNT(*) FROM detector_checks")->fetchColumn();
$total_threats = $pdo->query("SELECT COUNT(*) FROM detector_checks WHERE verdict LIKE '%High%'")->fetchColumn();

$users = $pdo->query("SELECT id, name, email, department, created_at FROM users WHERE role = 'user' ORDER BY created_at DESC")->fetchAll();
$logs  = $pdo->query("SELECT dc.*, u.name as user_name, u.email as user_email FROM detector_checks dc LEFT JOIN users u ON dc.user_id = u.id ORDER BY dc.created_at DESC")->fetchAll();
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>PhishShield — Admin Dashboard</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">
<nav class="navbar navbar-dark bg-danger px-4">
  <span class="navbar-brand">⚙️ Admin Control Panel</span>
  <div>
    <span class="text-white me-3">Admin: <strong><?= htmlspecialchars($_SESSION['user_name']) ?></strong></span>
    <a href="logout.php" class="btn btn-dark btn-sm">Logout</a>
  </div>
</nav>
<div class="container py-5">
  <div class="row mb-4">
    <div class="col-md-4"><div class="card bg-primary text-white"><div class="card-body"><h5>Total Users</h5><h2><?= $total_users ?></h2></div></div></div>
    <div class="col-md-4"><div class="card bg-info text-white"><div class="card-body"><h5>Total Scans</h5><h2><?= $total_scans ?></h2></div></div></div>
    <div class="col-md-4"><div class="card bg-danger text-white"><div class="card-body"><h5>Threats Detected</h5><h2><?= $total_threats ?></h2></div></div></div>
  </div>

  <h4 class="mb-3">Registered Users</h4>
  <div class="card mb-5"><div class="card-body p-0">
    <table class="table table-striped mb-0">
      <thead class="table-dark"><tr><th>ID</th><th>Name</th><th>Email</th><th>Registered</th></tr></thead>
      <tbody>
        <?php foreach ($users as $u): ?>
          <tr><td><?= $u['id'] ?></td><td><?= htmlspecialchars($u['name']) ?></td><td><?= htmlspecialchars($u['email']) ?></td><td><?= date('M d, Y', strtotime($u['created_at'])) ?></td></tr>
        <?php endforeach; ?>
      </tbody>
    </table>
  </div></div>

  <h4 class="mb-3">Phishing Logs</h4>
  <div class="card"><div class="card-body p-0">
    <table class="table table-hover mb-0">
      <thead class="table-dark"><tr><th>ID</th><th>User</th><th>Verdict</th><th>Score</th><th>Snippet</th><th>Date</th></tr></thead>
      <tbody>
        <?php foreach ($logs as $l): ?>
          <tr>
            <td><?= $l['id'] ?></td>
            <td><?= htmlspecialchars($l['user_name'] ?? 'Unknown') ?></td>
            <td><span class="badge bg-<?= str_contains($l['verdict'], 'High') ? 'danger' : 'success' ?>"><?= htmlspecialchars($l['verdict']) ?></span></td>
            <td><strong><?= $l['risk_score'] ?>/100</strong></td>
            <td><code><?= htmlspecialchars(substr($l['input_content'], 0, 40)) ?>...</code></td>
            <td><?= date('M d, Y H:i', strtotime($l['created_at'])) ?></td>
          </tr>
        <?php endforeach; ?>
      </tbody>
    </table>
  </div></div>
</div>
</body>
</html>