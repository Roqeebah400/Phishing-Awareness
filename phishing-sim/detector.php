<?php
// detector.php — Phishing Email Detector
require_once __DIR__ . '/db.php';

$result = null;
$score = 0;
$flags = [];
$email_text = '';
$sender = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email_text = trim($_POST['email_text'] ?? '');
    $sender = trim($_POST['sender'] ?? '');

    if ($email_text !== '') {

        $urgency_words = ['urgent', 'immediately', 'verify your account', 'suspended', 'act now',
                           'limited time', 'click here', 'confirm your identity', 'unusual activity',
                           'locked', 'expire', 'final notice'];
        $found_urgency = [];
        foreach ($urgency_words as $w) {
            if (stripos($email_text, $w) !== false) $found_urgency[] = $w;
        }
        if ($found_urgency) {
            $score += 20;
            $flags[] = "Urgency/pressure language detected: " . implode(', ', $found_urgency);
        }

        $sensitive_words = ['password', 'ssn', 'social security', 'credit card', 'bank account', 'pin number', 'login credentials'];
        $found_sensitive = [];
        foreach ($sensitive_words as $w) {
            if (stripos($email_text, $w) !== false) $found_sensitive[] = $w;
        }
        if ($found_sensitive) {
            $score += 25;
            $flags[] = "Requests sensitive information: " . implode(', ', $found_sensitive);
        }

        preg_match_all('/https?:\/\/[^\s"\'<>]+/i', $email_text, $matches);
        $urls = $matches[0];
        $suspicious_urls = [];
        foreach ($urls as $url) {
            $host = parse_url($url, PHP_URL_HOST);
            if (!$host) continue;

            if (filter_var($host, FILTER_VALIDATE_IP)) {
                $suspicious_urls[] = "$url (uses raw IP address instead of a domain)";
                continue;
            }
            $shorteners = ['bit.ly','tinyurl.com','t.co','goo.gl','ow.ly','is.gd'];
            foreach ($shorteners as $s) {
                if (stripos($host, $s) !== false) {
                    $suspicious_urls[] = "$url (uses a link shortener, destination hidden)";
                    break;
                }
            }
            $bad_tlds = ['.xyz', '.top', '.zip', '.rest', '.click', '.support', '.tk'];
            foreach ($bad_tlds as $tld) {
                if (str_ends_with(strtolower($host), $tld)) {
                    $suspicious_urls[] = "$url (unusual top-level domain: $tld)";
                    break;
                }
            }
            if (preg_match('/-(login|secure|verify|account|update|support)\b/i', $host)) {
                $suspicious_urls[] = "$url (domain uses brand-lookalike wording)";
            }
        }
        if ($suspicious_urls) {
            $score += 25;
            $flags[] = "Suspicious link(s) found: " . implode(' | ', $suspicious_urls);
        } elseif ($urls) {
            $flags[] = count($urls) . " link(s) found — no obvious red flags, but always hover to confirm destination.";
        }

        if ($sender !== '') {
            $sender_domain = substr(strrchr($sender, "@"), 1);
            if ($sender_domain) {
                $free_providers = ['gmail.com','yahoo.com','outlook.com','hotmail.com'];
                if (in_array(strtolower($sender_domain), $free_providers) &&
                    preg_match('/\b(bank|support|security|hr|payroll|it[\s\-]?dept)\b/i', $email_text)) {
                    $score += 15;
                    $flags[] = "Sender uses a free email provider ($sender_domain) but claims to be an official department.";
                }
            }
        }

        if (preg_match('/\b(dear customer|dear user|dear valued member|dear account holder)\b/i', $email_text)) {
            $score += 10;
            $flags[] = "Generic greeting used instead of your actual name — common in mass phishing emails.";
        }

        if (preg_match('/(!!!|\?\?\?|[A-Z]{6,})/', $email_text)) {
            $score += 5;
            $flags[] = "Excessive punctuation or all-caps text detected — common attention-grabbing tactic.";
        }

        $score = min($score, 100);

        if ($score >= 60) {
            $result = ['label' => 'High Risk — Likely Phishing', 'color' => 'danger'];
        } elseif ($score >= 30) {
            $result = ['label' => 'Medium Risk — Be Cautious', 'color' => 'warning'];
        } else {
            $result = ['label' => 'Low Risk — No Strong Red Flags', 'color' => 'success'];
        }

        try {
            $stmt = $pdo->prepare("INSERT INTO detector_checks (employee_id, risk_score, flags_count, verdict) VALUES (:eid, :score, :fc, :verdict)");
            $stmt->execute([
                ':eid' => isset($_GET['eid']) ? (int)$_GET['eid'] : null,
                ':score' => $score,
                ':fc' => count($flags),
                ':verdict' => $result['label']
            ]);
        } catch (\Exception $e) {}
    }
}
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>PhishShield — Email Detector</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">
<nav class="navbar navbar-dark bg-dark shadow-sm">
  <div class="container">
    <span class="navbar-brand mb-0 h1">🛡️ PhishShield — Email Detector</span>
    <div>
      <a href="manage.php" class="btn btn-outline-light btn-sm me-2">Admin</a>
      <a href="dashboard.php" class="btn btn-outline-light btn-sm">Dashboard</a>
    </div>
  </div>
</nav>

<div class="container py-5">
  <div class="row justify-content-center">
    <div class="col-lg-8">
      <div class="card shadow-sm mb-4">
        <div class="card-body">
          <h4>Check a Suspicious Email</h4>
          <p class="text-muted">Paste the full email content below. We'll scan it for common phishing red flags.</p>
          <form method="post">
            <div class="mb-3">
              <label class="form-label">Sender's email address (optional)</label>
              <input type="text" name="sender" class="form-control" placeholder="e.g. support@paypa1-secure.com" value="<?= htmlspecialchars($sender) ?>">
            </div>
            <div class="mb-3">
              <label class="form-label">Email content</label>
              <textarea name="email_text" rows="8" class="form-control" placeholder="Paste the email text here..." required><?= htmlspecialchars($email_text) ?></textarea>
            </div>
            <button type="submit" class="btn btn-primary">Analyze Email</button>
          </form>
        </div>
      </div>

      <?php if ($result): ?>
      <div class="card shadow-sm border-<?= $result['color'] ?>">
        <div class="card-body">
          <h5>Result: <span class="badge bg-<?= $result['color'] ?>"><?= $result['label'] ?></span></h5>
          <p class="mb-2">Risk Score: <strong><?= $score ?>/100</strong></p>
          <div class="progress mb-3" style="height:10px;">
            <div class="progress-bar bg-<?= $result['color'] ?>" style="width: <?= $score ?>%;"></div>
          </div>
          <?php if ($flags): ?>
            <h6>Red Flags Detected:</h6>
            <ul>
              <?php foreach ($flags as $f): ?>
                <li><?= htmlspecialchars($f) ?></li>
              <?php endforeach; ?>
            </ul>
          <?php else: ?>
            <p class="text-muted">No red flags detected — but always stay cautious with unexpected emails.</p>
          <?php endif; ?>
        </div>
      </div>
      <?php endif; ?>
    </div>
  </div>
</div>
</body>
</html>