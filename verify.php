<?php
// verify.php — lightweight viewer for recent tracking events (safe; never shows passwords)
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/auth.php';

try {
  $stmt = $pdo->query("SELECT t.id, t.action_type, t.ip_address, t.user_agent, t.timestamp, e.email AS employee_email, e.department, c.campaign_name FROM tracking_logs t LEFT JOIN employees e ON e.id = t.employee_id LEFT JOIN campaigns c ON c.id = t.campaign_id ORDER BY t.timestamp DESC LIMIT 100");
   $rows = $stmt->fetchAll();
} catch (\Exception $e) {
    $rows = [];
}
?>
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>PhishShield — Recent Events</title>
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

<div class="ps-shell ps-page">
  <h1 style="font-size:24px;">Recent tracking events</h1>
  <p style="margin-bottom:20px;">Shows the last 100 events. No secrets are ever displayed.</p>

  <div class="ps-card ps-card-flush">
    <div class="ps-table-wrap">
      <table class="ps-table">
        <thead>
          <tr>
            <th>ID</th><th>Time</th><th>Action</th><th>Employee</th><th>Dept</th><th>Campaign</th><th>IP</th><th>Meta</th>
          </tr>
        </thead>
        <tbody>
          <?php if ($rows): ?>
            <?php foreach($rows as $r): ?>
            <tr>
              <td><?= htmlspecialchars($r['id']) ?></td>
              <td><?= htmlspecialchars($r['timestamp']) ?></td>
              <td>
                <?php
                  $actionBadge = match($r['action_type']) {
                    'sent' => 'ps-badge-muted',
                    'clicked' => 'ps-badge-warn',
                    'submitted_data' => 'ps-badge-danger',
                    default => 'ps-badge-muted',
                  };
                ?>
                <span class="ps-badge <?= $actionBadge ?>"><?= htmlspecialchars($r['action_type']) ?></span>
              </td>
              <td><?= htmlspecialchars($r['employee_email'] ?? 'Unknown') ?></td>
              <td><?= htmlspecialchars($r['department'] ?? '') ?></td>
              <td><?= htmlspecialchars($r['campaign_name'] ?? '') ?></td>
              <td class="ps-small"><?= htmlspecialchars($r['ip_address'] ?? '') ?></td>
              <td class="ps-small"><?= htmlspecialchars($r['user_agent'] ?? '') ?></td>
           </tr>
            <?php endforeach; ?>
          <?php else: ?>
            <tr><td colspan="8"><div class="ps-empty">No tracking events yet.</div></td></tr>
          <?php endif; ?>
        </tbody>
      </table>
    </div>
  </div>
</div>
</body>
</html>