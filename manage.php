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

  <link
    href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css"
    rel="stylesheet"
  >

</head>

<body class="bg-light">


<nav class="navbar navbar-dark bg-danger px-4">

  <span class="navbar-brand">
    ⚙️ Admin Control Panel
  </span>

  <div>

       <a href="manage_employees.php" class="btn btn-outline-light btn-sm me-2">
      Employees & Campaigns
    </a>

    <a href="send_email.php" class="btn btn-outline-light btn-sm me-2">
      Send Campaign
    </a>

    <a href="settings.php" class="btn btn-outline-light btn-sm me-2">
      Email Settings
    </a>

    <span class="text-white me-3">
      Admin:
      <strong>
        <?= htmlspecialchars($_SESSION['user_name']) ?>
      </strong>
    </span>

    <a href="logout.php" class="btn btn-dark btn-sm">
      Logout
    </a>

  </div>

</nav>


<div class="container py-5">

  <?php if ($error): ?><div class="alert alert-danger"><?= htmlspecialchars($error) ?></div><?php endif; ?>
  <?php if ($success): ?><div class="alert alert-success"><?= htmlspecialchars($success) ?></div><?php endif; ?>

  <div class="row mb-4">

    <div class="col-md-4">

      <div class="card bg-primary text-white">

        <div class="card-body">

          <h5>Total Users</h5>

          <h2>
            <?= $total_users ?>
          </h2>

        </div>

      </div>

    </div>

    <div class="col-md-4">

      <div class="card bg-info text-white">

        <div class="card-body">

          <h5>Total Scans</h5>

          <h2>
            <?= $total_scans ?>
          </h2>

        </div>

      </div>

    </div>

    <div class="col-md-4">

      <div class="card bg-danger text-white">

        <div class="card-body">

          <h5>Threats Detected</h5>

          <h2>
            <?= $total_threats ?>
          </h2>

        </div>

      </div>

    </div>

  </div>

    <form method="get" class="mb-3">
    <label class="form-label">Filter by Campaign</label>
    <select name="campaign_id" class="form-select w-auto d-inline-block" onchange="this.form.submit()">
      <option value="">All Campaigns (Combined)</option>
      <?php foreach ($all_campaigns as $ac): ?>
        <option value="<?= $ac['id'] ?>" <?= $selected_campaign == $ac['id'] ? 'selected' : '' ?>>
          <?= htmlspecialchars($ac['campaign_name']) ?>
        </option>
      <?php endforeach; ?>
    </select>
  </form>

  <div class="row mb-4">
    <div class="col-md-4">
      <div class="card bg-secondary text-white">
        <div class="card-body">
          <h5>Emails Sent</h5>
          <h2><?= $sent_count ?></h2>
        </div>
      </div>
    </div>
    <div class="col-md-4">
      <div class="card bg-warning text-dark">
        <div class="card-body">
          <h5>Click Rate</h5>
          <h2><?= $click_rate ?>%</h2>
        </div>
      </div>
    </div>
    <div class="col-md-4">
      <div class="card bg-dark text-white">
        <div class="card-body">
          <h5>Credential Compromise Rate</h5>
          <h2><?= $compromise_rate ?>%</h2>
        </div>
      </div>
    </div>
  </div>


  <!-- REGISTERED USERS -->

  <h4 class="mb-3">
    Registered Users
  </h4>

  <div class="card mb-3">
    <div class="card-body">
      <h6 class="mb-3">Create a New User Account</h6>
      <form method="post" class="row g-2 align-items-end">
        <input type="hidden" name="create_user" value="1">
        <div class="col-md-3">
          <label class="form-label">Full Name</label>
          <input type="text" name="new_name" class="form-control" required>
        </div>
        <div class="col-md-3">
          <label class="form-label">Email</label>
          <input type="email" name="new_email" class="form-control" required>
        </div>
        <div class="col-md-3">
          <label class="form-label">Password</label>
          <input type="text" name="new_password" class="form-control" placeholder="min 6 characters" required>
        </div>
        <div class="col-md-3">
          <button type="submit" class="btn btn-primary w-100">Create Account</button>
        </div>
      </form>
      <small class="text-muted d-block mt-2">Share the email and password with the person so they can log in at /login.php. Accounts you create here only appear on your dashboard — not visible to other admins.</small>
    </div>
  </div>

  <div class="card mb-5">

    <div class="card-body p-0">

      <table class="table table-striped mb-0">

        <thead class="table-dark">

          <tr>

            <th>ID</th>
            <th>Name</th>
            <th>Email</th>
            <th>Registered</th>
            <th>Action</th>

          </tr>

        </thead>


        <tbody>

          <?php foreach ($users as $u): ?>

            <tr>

              <td>
                <?= $u['id'] ?>
              </td>

              <td>
                <?= htmlspecialchars($u['name']) ?>
              </td>

              <td>
                <?= htmlspecialchars($u['email']) ?>
              </td>

              <td>
                <?= date('M d, Y', strtotime($u['created_at'])) ?>
              </td>

              <td>

                <form
                  action="delete_user.php"
                  method="POST"
                  style="display:inline;"
                  onsubmit="return confirm('Are you sure you want to delete this user?');"
                >

                  <input
                    type="hidden"
                    name="user_id"
                    value="<?= htmlspecialchars($u['id']) ?>"
                  >

                  <button
                    type="submit"
                    class="btn btn-danger btn-sm"
                  >
                    🗑️ Delete
                  </button>

                </form>

              </td>

            </tr>

          <?php endforeach; ?>

        </tbody>

      </table>

    </div>

  </div>



  <!-- PHISHING LOGS -->

  <h4 class="mb-3">
    Phishing Logs
  </h4>


  <div class="card">

    <div class="card-body p-0">

      <table class="table table-hover mb-0">

        <thead class="table-dark">

          <tr>

            <th>ID</th>

            <th>User</th>

            <th>Verdict</th>

            <th>Score</th>

            <th>Snippet</th>

            <th>Date</th>

            <!-- ADDED -->
            <th>Action</th>

          </tr>

        </thead>


        <tbody>

          <?php foreach ($logs as $l): ?>

            <tr>

              <td>
                <?= $l['id'] ?>
              </td>


              <td>
                <?= htmlspecialchars($l['user_name'] ?? 'Unknown') ?>
              </td>


              <td>

                <span
                  class="badge bg-<?= str_contains($l['verdict'], 'High') ? 'danger' : 'success' ?>"
                >

                  <?= htmlspecialchars($l['verdict']) ?>

                </span>

              </td>


              <td>

                <strong>
                  <?= $l['risk_score'] ?>/100
                </strong>

              </td>


              <td>

                <code>
                  <?= htmlspecialchars(substr($l['input_content'], 0, 40)) ?>...
                </code>

              </td>


              <td>

                <?= date(
                  'M d, Y H:i',
                  strtotime($l['created_at'])
                ) ?>

              </td>


              <!-- DELETE BUTTON ADDED HERE -->

              <td>

                <form
                  action="delete_log.php"
                  method="POST"
                  style="display:inline;"
                  onsubmit="return confirm('Are you sure you want to delete this phishing log?');"
                >

                  <input
                    type="hidden"
                    name="log_id"
                    value="<?= htmlspecialchars($l['id']) ?>"
                  >

                  <button
                    type="submit"
                    class="btn btn-danger btn-sm"
                  >
                    🗑️ Delete
                  </button>

                </form>

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