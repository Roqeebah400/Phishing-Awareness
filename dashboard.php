<?php
// dashboard.php — User History Dashboard
require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/db.php';

requireUser();

$stmt = $pdo->prepare("SELECT * FROM detector_checks WHERE user_id = :uid ORDER BY created_at DESC");
$stmt->execute([':uid' => $_SESSION['user_id']]);
$scans = $stmt->fetchAll();

$total_scans = count($scans);
$high_count = count(array_filter($scans, fn($s) => str_contains($s['verdict'], 'High')));
$avg_score = $total_scans ? round(array_sum(array_column($scans, 'risk_score')) / $total_scans) : 0;
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>PhishShield — My Dashboard</title>
  <link href="assets/phishshield.css" rel="stylesheet">
</head>
<body class="ps-body">

<nav class="ps-nav">
  <div class="ps-nav-inner">
    <div class="ps-brand"><span class="ps-brand-glyph"></span>PhishShield</div>
    <div class="ps-nav-actions">
      <span class="ps-nav-user">Signed in as <strong><?= htmlspecialchars($_SESSION['user_name'] ?? 'User') ?></strong></span>
      <a href="detector.php" class="ps-btn ps-btn-primary ps-btn-sm">Scan an email</a>
      <a href="logout.php" class="ps-btn ps-btn-ghost ps-btn-sm">Logout</a>
    </div>
  </div>
</nav>

<div class="ps-shell ps-page">
  <h1 style="font-size:26px;">My scan history</h1>
  <p style="margin-bottom:24px;">Every email you've checked with the detector, and how it was scored.</p>

  <div class="ps-stats">
    <div class="ps-stat accent-blue">
      <div class="ps-stat-label">Total scans</div>
      <div class="ps-stat-value"><?= $total_scans ?></div>
    </div>
    <div class="ps-stat accent-danger">
      <div class="ps-stat-label">High-risk results</div>
      <div class="ps-stat-value"><?= $high_count ?></div>
    </div>
    <div class="ps-stat accent-good">
      <div class="ps-stat-label">Average risk score</div>
      <div class="ps-stat-value"><?= $avg_score ?>/100</div>
    </div>
  </div>

  <div class="ps-card ps-card-flush">
    <div class="ps-table-wrap">
      <table class="ps-table">
        <thead>
          <tr>
            <th>#</th>
            <th>Verdict</th>
            <th>Risk score</th>
            <th>Flags</th>
            <th>Date</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
        <?php if ($scans): ?>
          <?php foreach ($scans as $i => $s): ?>
            <?php
              $badgeClass = str_contains($s['verdict'], 'High') ? 'ps-badge-danger'
                          : (str_contains($s['verdict'], 'Medium') ? 'ps-badge-warn' : 'ps-badge-good');
            ?>
            <tr>
              <td><?= $i + 1 ?></td>
              <td><span class="ps-badge <?= $badgeClass ?>"><?= htmlspecialchars($s['verdict']) ?></span></td>
              <td><strong><?= htmlspecialchars($s['risk_score']) ?>/100</strong></td>
              <td><?= htmlspecialchars($s['flags_count']) ?></td>
              <td><?= date('M d, Y H:i', strtotime($s['created_at'])) ?></td>
              <td>
                <form action="delete_scan.php" method="POST" onsubmit="return confirm('Are you sure you want to delete this scan?');">
                  <input type="hidden" name="scan_id" value="<?= (int)$s['id'] ?>">
                  <button type="submit" class="ps-btn ps-btn-danger ps-btn-sm">Delete</button>
                </form>
              </td>
            </tr>
          <?php endforeach; ?>
        <?php else: ?>
          <tr>
            <td colspan="6">
              <div class="ps-empty">
                <p style="margin-bottom:16px;">You haven't scanned any emails yet. Nothing to show here until you run your first check.</p>
                <a href="detector.php" class="ps-btn ps-btn-primary ps-btn-sm">Scan your first email →</a>
              </div>
            </td>
          </tr>
        <?php endif; ?>
        </tbody>
      </table>
    </div>
  </div>
</div>

</body>
</html>