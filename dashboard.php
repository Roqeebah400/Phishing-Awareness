<?php
require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/db.php';

try {
    $total_delivered = (int)$pdo->query("SELECT COUNT(*) FROM campaigns")->fetchColumn();
} catch (\Exception $e) { $total_delivered = 0; }

try {
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM tracking_logs WHERE action = :a");
    $stmt->execute([':a' => 'clicked']);
    $total_clicks = (int)$stmt->fetchColumn();
} catch (\Exception $e) { $total_clicks = 0; }

try {
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM tracking_logs WHERE action = :a");
    $stmt->execute([':a' => 'submitted_data']);
    $total_compromised = (int)$stmt->fetchColumn();
} catch (\Exception $e) { $total_compromised = 0; }

try {
    $total_detector_checks = (int)$pdo->query("SELECT COUNT(*) FROM detector_checks")->fetchColumn();
} catch (\Exception $e) { $total_detector_checks = 0; }

$departments = [];
try {
    $sql = "SELECT e.department,
                   COUNT(DISTINCT e.id) AS total_staff,
                   SUM(CASE WHEN t.action = 'clicked' THEN 1 ELSE 0 END) AS total_clicks,
                   SUM(CASE WHEN t.action = 'submitted_data' THEN 1 ELSE 0 END) AS total_failures
            FROM employees e
            LEFT JOIN tracking_logs t ON t.employee_id = e.id
            GROUP BY e.department
            ORDER BY total_staff DESC";
    $stmt = $pdo->query($sql);
    $departments = $stmt->fetchAll();
} catch (\Exception $e) {
    $departments = [];
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PhishShield Admin Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>body{background:#f8f9fa}</style>
</head>
<body class="bg-light">

    <nav class="navbar navbar-dark bg-dark shadow-sm">
        <div class="container">
            <span class="navbar-brand mb-0 h1">🛡️ PhishShield Admin Center</span>
            <div>
              <a href="manage.php" class="btn btn-outline-light btn-sm me-2">Manage</a>
              <a href="detector.php" class="btn btn-outline-light btn-sm">Detector</a>
              <a href="logout.php" class="btn btn-outline-light btn-sm">Logout</a>
            </div>
        </div>
    </nav>

    <div class="container my-5">
        <div class="d-flex justify-content-between align-items-center mb-4">
            <h2>Simulation Analytics Overview</h2>
            <span class="badge bg-success p-2">System Status: Active</span>
        </div>

        <div class="row g-4 mb-5">
            <div class="col-md-3">
                <div class="card bg-white border-0 shadow-sm p-4 border-start border-primary border-4">
                    <div class="text-muted small uppercase fw-bold">Total Delivered Simulations</div>
                    <h2 class="fw-bold mt-2 text-primary"><?= $total_delivered ?></h2>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card bg-white border-0 shadow-sm p-4 border-start border-warning border-4">
                    <div class="text-muted small uppercase fw-bold">Total Link Clicks</div>
                    <h2 class="fw-bold mt-2 text-warning"><?= $total_clicks ?></h2>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card bg-white border-0 shadow-sm p-4 border-start border-danger border-4">
                    <div class="text-muted small uppercase fw-bold">Credentials Compromised</div>
                    <h2 class="fw-bold mt-2 text-danger"><?= $total_compromised ?></h2>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card bg-white border-0 shadow-sm p-4 border-start border-info border-4">
                    <div class="text-muted small uppercase fw-bold">Detector Checks Run</div>
                    <h2 class="fw-bold mt-2 text-info"><?= $total_detector_checks ?></h2>
                </div>
            </div>
        </div>

        <div class="card border-0 shadow-sm">
            <div class="card-header bg-white py-3 fw-bold border-0">
                🏢 Departmental Vulnerability Assessment
            </div>
            <div class="card-body p-0">
                <table class="table table-hover mb-0 align-middle">
                    <thead class="table-light">
                        <tr>
                            <th class="ps-4">Department Name</th>
                            <th>Staff Tested</th>
                            <th>Clicks Logged</th>
                            <th>Data Leaked</th>
                            <th class="pe-4 text-end">Risk Profile Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach($departments as $dept):
                            $fail_rate = $dept['total_staff'] > 0 ? round(($dept['total_failures'] / $dept['total_staff']) * 100) : 0;
                            if ($fail_rate >= 60) {
                                $badge_color = 'bg-danger';
                                $risk_status = 'Critical Risk';
                            } elseif ($fail_rate > 0 && $fail_rate < 60) {
                                $badge_color = 'bg-warning text-dark';
                                $risk_status = 'Medium Risk';
                            } else {
                                $badge_color = 'bg-success';
                                $risk_status = 'Secure';
                            }
                        ?>
                        <tr>
                            <td class="ps-4 fw-bold text-secondary"><?= htmlspecialchars($dept['department']) ?></td>
                            <td><?= $dept['total_staff'] ?></td>
                            <td><?= $dept['total_clicks'] ?></td>
                            <td><?= $dept['total_failures'] ?></td>
                            <td class="pe-4 text-end">
                                <span class="badge <?= $badge_color ?> px-3 py-2 rounded-pill">
                                    <?= $fail_rate ?>% (<?= $risk_status ?>)
                                </span>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

</body>
</html>