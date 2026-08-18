<?php
// detector.php — Phishing Detection Engine
require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/db.php';

requireUser();

$result = null;
$score = 0;
$flags = [];
$email_text = '';
$sender = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email_text = trim($_POST['email_text'] ?? '');
    $sender     = trim($_POST['sender'] ?? '');

    if ($email_text !== '') {

        // 1. Urgency Language
        $urgency_words = ['urgent', 'immediately', 'verify your account', 'suspended', 'act now', 'click here', 'unusual activity', 'locked'];
        $found_urgency = [];
        foreach ($urgency_words as $w) {
            if (stripos($email_text, $w) !== false) $found_urgency[] = $w;
        }
        if ($found_urgency) {
            $score += 20;
            $flags[] = "Urgency words detected: " . implode(', ', $found_urgency);
        }

        // 2. Sensitive Data Requests
        $sensitive_words = ['password', 'ssn', 'social security', 'credit card', 'bank account', 'pin number'];
        $found_sensitive = [];
        foreach ($sensitive_words as $w) {
            if (stripos($email_text, $w) !== false) $found_sensitive[] = $w;
        }
        if ($found_sensitive) {
            $score += 25;
            $flags[] = "Sensitive data requested: " . implode(', ', $found_sensitive);
        }

        // 3. Link Analysis
        preg_match_all('/https?:\/\/[^\s"\'<>]+/i', $email_text, $matches);
        $urls = $matches[0];
        $suspicious_urls = [];
        foreach ($urls as $url) {
            $host = parse_url($url, PHP_URL_HOST);
            if (!$host) continue;

            if (filter_var($host, FILTER_VALIDATE_IP)) {
                $suspicious_urls[] = "$url (uses IP address)";
                continue;
            }
            $shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl'];
            foreach ($shorteners as $s) {
                if (stripos($host, $s) !== false) {
                    $suspicious_urls[] = "$url (shortened link)";
                    break;
                }
            }
        }
        if ($suspicious_urls) {
            $score += 25;
            $flags[] = "Suspicious links found: " . implode(' | ', $suspicious_urls);
        }

        // 4. Generic Greetings
        if (preg_match('/\b(dear customer|dear user|dear valued member)\b/i', $email_text)) {
            $score += 10;
            $flags[] = "Generic greeting detected.";
        }

        $score = min($score, 100);

        if ($score >= 60) {
            $result = ['label' => 'High Risk — Likely Phishing', 'color' => 'danger'];
        } elseif ($score >= 30) {
            $result = ['label' => 'Medium Risk — Be Cautious', 'color' => 'warning'];
        } else {
            $result = ['label' => 'Low Risk — Safe Email', 'color' => 'success'];
        }

        // Insert Scan Log
        try {
            $stmt = $pdo->prepare("INSERT INTO detector_checks (user_id, input_content, risk_score, flags_count, verdict) VALUES (:uid, :content, :score, :fc, :verdict)");
            $stmt->execute([
                ':uid'     => $_SESSION['user_id'],
                ':content' => $email_text,
                ':score'   => $score,
                ':fc'      => count($flags),
                ':verdict' => $result['label']
            ]);
        } catch (PDOException $e) {}
    }
}
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>PhishShield — Email Detector</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">
<nav class="navbar navbar-dark bg-dark">
  <div class="container">
    <span class="navbar-brand">🛡️ PhishShield</span>
    <div class="text-light">
      Welcome, <strong><?= htmlspecialchars($_SESSION['user_name'] ?? 'User') ?></strong>
      <a href="dashboard.php" class="btn btn-outline-light btn-sm ms-2">My Dashboard</a>
      <a href="logout.php" class="btn btn-danger btn-sm ms-2">Logout</a>
    </div>
  </div>
</nav>
<div class="container py-5">
  <div class="row justify-content-center">
    <div class="col-lg-8">
      <div class="card shadow-sm mb-4">
        <div class="card-body">
          <h4>Scan Suspicious Email</h4>
          <form method="post">
            <div class="mb-3">
              <label>Sender Email (optional)</label>
              <input type="text" name="sender" class="form-control" value="<?= htmlspecialchars($sender) ?>">
            </div>
            <div class="mb-3">
              <label>Email Content</label>
              <textarea name="email_text" rows="7" class="form-control" required><?= htmlspecialchars($email_text) ?></textarea>
            </div>
            <button type="submit" class="btn btn-primary">Scan Email</button>
          </form>
        </div>
      </div>
      <?php if ($result): ?>
      <div class="card border-<?= $result['color'] ?>">
        <div class="card-body">
          <h5>Verdict: <span class="badge bg-<?= $result['color'] ?>"><?= $result['label'] ?></span></h5>
          <p>Risk Score: <strong><?= $score ?>/100</strong></p>
          <?php if ($flags): ?>
            <h6>Red Flags:</h6>
            <ul><?php foreach ($flags as $f): ?><li><?= htmlspecialchars($f) ?></li><?php endforeach; ?></ul>
          <?php endif; ?>
        </div>
      </div>
      <?php endif; ?>
    </div>
  </div>
</div>
</body>
</html>