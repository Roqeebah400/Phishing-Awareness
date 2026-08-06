<?php
require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/db.php';

$message = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['add_employee'])) {
    $name = trim($_POST['name'] ?? '');
    $email = trim($_POST['email'] ?? '');
    $department = trim($_POST['department'] ?? 'Unassigned');
    if ($name && $email) {
        try {
            $stmt = $pdo->prepare("INSERT INTO employees (name, email, department) VALUES (:n, :e, :d)");
            $stmt->execute([':n' => $name, ':e' => $email, ':d' => $department]);
            $message = "Employee added successfully.";
        } catch (\Exception $e) {
            $message = "Error adding employee: " . $e->getMessage();
        }
    } else {
        $message = "Name and email are required.";
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['add_campaign'])) {
    $cname = trim($_POST['campaign_name'] ?? '');
    if ($cname) {
        try {
            $stmt = $pdo->prepare("INSERT INTO campaigns (name, delivered_at) VALUES (:n, NOW())");
            $stmt->execute([':n' => $cname]);
            $message = "Campaign created successfully.";
        } catch (\Exception $e) {
            $message = "Error creating campaign: " . $e->getMessage();
        }
    } else {
        $message = "Campaign name is required.";
    }
}

$employees = $pdo->query("SELECT * FROM employees ORDER BY id DESC")->fetchAll();
$campaigns = $pdo->query("SELECT * FROM campaigns ORDER BY id DESC")->fetchAll();

$base_url = "http://localhost/phishing-sim/index.php";
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>PhishShield — Manage Campaigns & Employees</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>body{background:#f8f9fa}</style>
</head>
<body>
<nav class="navbar navbar-dark bg-dark shadow-sm">
  <div class="container">
    <span class="navbar-brand mb-0 h1">🛡️ PhishShield Admin</span>
    <div>
      <a href="detector.php" class="btn btn-outline-light btn-sm me-2">Detector</a>
      <a href="dashboard.php" class="btn btn-outline-light btn-sm">Dashboard</a>
      <a href="logout.php" class="btn btn-outline-light btn-sm">Logout</a>
    </div>
  </div>
</nav>

<div class="container my-5">

  <?php if ($message): ?>
    <div class="alert alert-info"><?= htmlspecialchars($message) ?></div>
  <?php endif; ?>

  <div class="row g-4">
    <div class="col-md-6">
      <div class="card shadow-sm">
        <div class="card-body">
          <h5 class="card-title">Add Employee</h5>
          <form method="post">
            <div class="mb-2">
              <label class="form-label">Name</label>
              <input type="text" name="name" class="form-control" required>
            </div>
            <div class="mb-2">
              <label class="form-label">Email</label>
              <input type="email" name="email" class="form-control" required>
            </div>
            <div class="mb-2">
              <label class="form-label">Department</label>
              <input type="text" name="department" class="form-control" placeholder="e.g. Sales">
            </div>
            <button type="submit" name="add_employee" value="1" class="btn btn-primary">Add Employee</button>
          </form>
        </div>
      </div>
    </div>

    <div class="col-md-6">
      <div class="card shadow-sm">
        <div class="card-body">
          <h5 class="card-title">Create Campaign</h5>
          <form method="post">
            <div class="mb-2">
              <label class="form-label">Campaign Name</label>
              <input type="text" name="campaign_name" class="form-control" placeholder="e.g. August Awareness Test" required>
            </div>
            <button type="submit" name="add_campaign" value="1" class="btn btn-primary">Create Campaign</button>
          </form>
        </div>
      </div>
    </div>
  </div>

  <div class="card shadow-sm mt-5">
    <div class="card-header bg-white fw-bold">🔗 Generated Simulation Links</div>
    <div class="card-body p-0">
      <table class="table table-striped mb-0">
        <thead>
          <tr>
            <th class="ps-3">Employee</th>
            <th>Campaign</th>
            <th>Link to Send</th>
            <th class="pe-3"></th>
          </tr>
        </thead>
        <tbody>
          <?php foreach ($campaigns as $c): foreach ($employees as $e):
              $link = $base_url . '?cid=' . $c['id'] . '&eid=' . $e['id'];
          ?>
          <tr>
            <td class="ps-3"><?= htmlspecialchars($e['name']) ?> (<?= htmlspecialchars($e['email']) ?>)</td>
            <td><?= htmlspecialchars($c['name']) ?></td>
            <td><code class="small"><?= htmlspecialchars($link) ?></code></td>
            <td class="pe-3 text-end">
              <button class="btn btn-sm btn-outline-secondary" onclick="navigator.clipboard.writeText('<?= htmlspecialchars($link) ?>'); this.textContent='Copied!'">Copy</button>
            </td>
          </tr>
          <?php endforeach; endforeach; ?>
          <?php if (!$employees || !$campaigns): ?>
          <tr><td colspan="4" class="text-center text-muted py-4">Add at least one employee and one campaign to generate links.</td></tr>
          <?php endif; ?>
        </tbody>
      </table>
    </div>
  </div>

</div>
</body>
</html>