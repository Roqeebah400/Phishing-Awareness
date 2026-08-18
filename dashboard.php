<?php
// dashboard.php — User History Dashboard
require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/db.php';

requireUser();

$stmt = $pdo->prepare("SELECT * FROM detector_checks WHERE user_id = :uid ORDER BY created_at DESC");
$stmt->execute([':uid' => $_SESSION['user_id']]);
$scans = $stmt->fetchAll();
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>PhishShield — User Dashboard</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">
<nav class="navbar navbar-dark bg-dark">
  <div class="container">
    <span class="navbar-brand">🛡️ PhishShield</span>
    <div>
      <a href="detector.php" class="btn btn-primary btn-sm">Scan Email</a>
      <a href="logout.php" class="btn btn-danger btn-sm">Logout</a>
    </div>
  </div>
</nav>
<div class="container py-5">
  <h3>My Scan History</h3>
  <div class="card shadow-sm">
    <div class="card-body p-0">
      <table class="table table-hover mb-0">
        <thead class="table-dark">
          <tr><th>#</th><th>Verdict</th><th>Risk Score</th><th>Flags</th><th>Date</th></tr>
        </thead>
        <tbody>
          <?php if ($scans): foreach ($scans as $i => $s): ?>
            <tr>
              <td><?= $i + 1 ?></td>
              <td><span class="badge bg-<?= str_contains($s['verdict'], 'High') ? 'danger' : (str_contains($s['verdict'], 'Medium') ? 'warning' : 'success') ?>"><?= htmlspecialchars($s['verdict']) ?></span></td>
              <td><strong><?= $s['risk_score'] ?>/100</strong></td>
              <td><?= $s['flags_count'] ?></td>
              <td><?= date('M d, Y H:i', strtotime($s['created_at'])) ?></td>
            </tr>
          <?php endforeach; else: ?>
            <tr><td colspan="5" class="text-center py-4">No scans recorded yet.</td></tr>
          <?php endif; ?>
        </tbody>
      </table>
    </div>
  </div>
</div>
</body>
</html>