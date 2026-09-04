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
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">
  <div class="container py-4">
    <h3>Recent Tracking Events</h3>
    <p class="text-muted">Shows last 100 events. No secrets are displayed.</p>
    <table class="table table-sm table-striped">
      <thead>
        <tr>
          <th>ID</th>
          <th>Time</th>
          <th>Action</th>
          <th>Employee</th>
          <th>Dept</th>
          <th>Campaign</th>
          <th>IP</th>
          <th>Meta</th>
        </tr>
      </thead>
      <tbody>
        <?php foreach($rows as $r): ?>
        <tr>
          <td><?= htmlspecialchars($r['id']) ?></td>
          <td><?= htmlspecialchars($r['timestamp']) ?></td>
          <td><?= htmlspecialchars($r['action_type']) ?></td>
          <td><?= htmlspecialchars($r['employee_email'] ?? 'Unknown') ?></td>
          <td><?= htmlspecialchars($r['department'] ?? '') ?></td>
          <td><?= htmlspecialchars($r['campaign_name'] ?? '') ?></td>
          <td><?= htmlspecialchars($r['ip_address'] ?? '') ?></td>
          <td><?= htmlspecialchars($r['user_agent'] ?? '') ?></td>
       </tr>
        <?php endforeach; ?>
      </tbody>
    </table>
  </div>
</body>
</html>