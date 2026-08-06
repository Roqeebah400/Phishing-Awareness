<?php
require_once __DIR__ . '/db.php';

function get_ip() {
    if (!empty($_SERVER['HTTP_CLIENT_IP'])) return $_SERVER['HTTP_CLIENT_IP'];
    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) return explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'])[0];
    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

$campaign_id = filter_input(INPUT_GET, 'cid', FILTER_VALIDATE_INT) ?: filter_input(INPUT_POST, 'cid', FILTER_VALIDATE_INT);
$employee_id = filter_input(INPUT_GET, 'eid', FILTER_VALIDATE_INT) ?: filter_input(INPUT_POST, 'eid', FILTER_VALIDATE_INT);

if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    if ($campaign_id && $employee_id) {
        $stmt = $pdo->prepare("INSERT INTO tracking_logs (campaign_id, employee_id, action, ip, user_agent, meta) VALUES (:cid, :eid, 'clicked', :ip, :ua, :meta)");
        $meta = json_encode(['ref' => $_SERVER['HTTP_REFERER'] ?? null]);
        try { $stmt->execute([':cid'=>$campaign_id, ':eid'=>$employee_id, ':ip'=>get_ip(), ':ua'=>substr($_SERVER['HTTP_USER_AGENT'] ?? '',0,512), ':meta'=>$meta]); } catch (\Exception $e) {}
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if ($campaign_id && $employee_id) {
        $stmt = $pdo->prepare("INSERT INTO tracking_logs (campaign_id, employee_id, action, ip, user_agent, meta) VALUES (:cid, :eid, 'submitted_data', :ip, :ua, :meta)");
        $meta = json_encode(['form_fields' => ['username' => isset($_POST['username']) ? 'present' : 'missing']]);
        try { $stmt->execute([':cid'=>$campaign_id, ':eid'=>$employee_id, ':ip'=>get_ip(), ':ua'=>substr($_SERVER['HTTP_USER_AGENT'] ?? '',0,512), ':meta'=>$meta]); } catch (\Exception $e) {}
    }
    header('Location: training.php?eid=' . $employee_id);
    exit;
}
?><!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Employee Portal — Sign In</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">
  <div class="container py-5">
    <div class="row justify-content-center">
      <div class="col-md-6">
        <div class="card shadow-sm">
          <div class="card-body">
            <h4 class="mb-3">Employee Portal</h4>
            <p class="text-muted">Please sign in to continue.</p>
            <form method="post" autocomplete="off">
              <input type="hidden" name="cid" value="<?= htmlspecialchars((string)($campaign_id ?? '')) ?>">
              <input type="hidden" name="eid" value="<?= htmlspecialchars((string)($employee_id ?? '')) ?>">
              <div class="mb-3">
                <label class="form-label">Email</label>
                <input name="username" type="email" class="form-control" required>
              </div>
              <div class="mb-3">
                <label class="form-label">Password</label>
                <input name="password" type="password" class="form-control" required>
              </div>
              <button class="btn btn-primary">Sign In</button>
            </form>
            <p class="mt-3 small text-muted">If this looks suspicious, close the page and report it to security.</p>
          </div>
        </div>
      </div>
    </div>
  </div>
</body>
</html>