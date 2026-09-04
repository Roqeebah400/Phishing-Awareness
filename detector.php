<?php
// detector.php — Phishing Detection Engine
require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/detector_helpers.php';

requireUser();

$result = null;
$score = 0;
$flags = [];
$api_notes = []; // soft notices when an external check couldn't run — never scored
$email_text = '';
$sender = '';
$db_error = null;
$ai_assessment = null;

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

                // Combination bonus: urgency + sensitive-data request together is the classic phishing pattern
        if ($found_urgency && $found_sensitive) {
            $score += 15;
            $flags[] = "Combination risk: urgency language paired with a sensitive-data request is a classic phishing pattern (+15 bonus).";
        }

        // 3. Link Analysis (shorteners / raw IPs + VirusTotal reputation)
        preg_match_all('/https?:\/\/[^\s"\'<>]+/i', $email_text, $matches);
        $urls = array_slice(array_unique($matches[0]), 0, 5); // cap external calls per scan
        $suspicious_urls = [];
        foreach ($urls as $url) {
            $host = parse_url($url, PHP_URL_HOST);
            if (!$host) continue;

            if (filter_var($host, FILTER_VALIDATE_IP)) {
                $suspicious_urls[] = "$url (uses IP address)";
                
            }
            $shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl'];
            foreach ($shorteners as $s) {
                if (stripos($host, $s) !== false) {
                    $suspicious_urls[] = "$url (shortened link)";
                    break;
                }
            }

            // VirusTotal reputation check
            $vt = checkUrlReputation($url);
            if ($vt['checked']) {
                if ($vt['malicious'] > 0) {
                    $score += 35;
                    $flags[] = "VirusTotal: flagged malicious by {$vt['malicious']} security vendor(s) — $url";
                } elseif ($vt['suspicious'] > 0) {
                    $score += 15;
                    $flags[] = "VirusTotal: flagged suspicious by {$vt['suspicious']} vendor(s) — $url";
                }
            } elseif ($vt['error']) {
                $api_notes[] = "VirusTotal check skipped for $url: {$vt['error']}";
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

                // 5. Sender Address Analysis
        if ($sender !== '') {
            $senderHost = null;

            if (filter_var($sender, FILTER_VALIDATE_EMAIL)) {
                $senderHost = strtolower(substr(strrchr($sender, "@"), 1));
            } elseif (preg_match('/<([^>]+)>/', $sender, $m) && filter_var($m[1], FILTER_VALIDATE_EMAIL)) {
                $senderHost = strtolower(substr(strrchr($m[1], "@"), 1));
            }

            if ($senderHost) {
                // WHOIS domain age check
                $whois = checkDomainAge($senderHost);
                if ($whois['checked']) {
                    if ($whois['age_days'] < 7) {
                        $score += 30;
                        $flags[] = "Domain '{$senderHost}' was registered only {$whois['age_days']} day(s) ago — very likely attack infrastructure.";
                    } elseif ($whois['age_days'] < 30) {
                        $score += 20;
                        $flags[] = "Domain '{$senderHost}' was registered {$whois['age_days']} day(s) ago — recently created domains are high-risk.";
                    }
                } elseif ($whois['error']) {
                    $api_notes[] = "WHOIS check skipped for {$senderHost}: {$whois['error']}";
                }

                $free_providers = ['gmail.com','yahoo.com','outlook.com','hotmail.com','aol.com','icloud.com','mail.com'];
                if (in_array($senderHost, $free_providers, true)
                    && preg_match('/\b(bank|support|billing|security|admin|hr|it[\s-]?department|payroll)\b/i', $email_text)) {
                    $score += 15;
                    $flags[] = "Sender uses a free email provider ($senderHost) but the message claims to be from an official department — legitimate organizations don't send official notices from Gmail/Yahoo/etc.";
                }

                if (filter_var($senderHost, FILTER_VALIDATE_IP)) {
                    $score += 20;
                    $flags[] = "Sender domain is a raw IP address ($senderHost) instead of a normal company domain.";
                }

                $trusted_domains = ['paypal.com','microsoft.com','google.com','apple.com','amazon.com','bankofamerica.com'];
                foreach ($trusted_domains as $td) {
                    if ($senderHost !== $td && levenshtein($senderHost, $td) <= 2) {
                        $score += 25;
                        $flags[] = "Sender domain ($senderHost) closely resembles a trusted domain ($td) — likely spoofing.";
                        break;
                    }
                }

                if (preg_match('/-(secure|login|verify|update|account)\b/i', $senderHost)) {
                    $score += 15;
                    $flags[] = "Sender domain ($senderHost) contains keywords often used to imitate a legitimate site.";
                }
            } else {
                $score += 5;
                $flags[] = "Sender field ($sender) isn't a recognizable email address — treat with caution.";
            }
        }

             // 6. AI Content Analysis (Groq LLM) — blends with the rule-based score
        $rule_score = $score; // keep the pure rule-based score before blending
        $ai = checkWithGroqLLM($email_text, $sender);
        if ($ai['checked']) {
            $score = max($rule_score, (int) round(($rule_score * 0.6) + ($ai['ai_score'] * 0.4)));
            $ai_assessment = ['score' => $ai['ai_score'], 'reasoning' => $ai['reasoning']];
        } elseif ($ai['error'] && isset($api_notes)) {
            $api_notes[] = "Groq AI check skipped: {$ai['error']}";
        }

        $score = min($score, 100);

        if ($score >= 60) {
            $result = ['label' => 'High Risk — Likely Phishing', 'color' => 'danger'];
        } elseif ($score >= 30) {
            $result = ['label' => 'Medium Risk — Be Cautious', 'color' => 'warning'];
        } else {
            $result = ['label' => 'Low Risk — Safe Email', 'color' => 'success'];
        }
        // Check user session key fallback
        $user_id = $_SESSION['user_id'] ?? $_SESSION['id'] ?? null;

        if ($user_id) {
            try {
                $stmt = $pdo->prepare("INSERT INTO detector_checks (user_id, input_content, risk_score, flags_count, verdict) VALUES (:uid, :content, :score, :fc, :verdict)");
                $stmt->execute([
                    ':uid'     => $user_id,
                    ':content' => $email_text,
                    ':score'   => $score,
                    ':fc'      => count($flags),
                    ':verdict' => $result['label']
                ]);
            } catch (PDOException $e) {
                $db_error = "Database Error: " . $e->getMessage();
            }
        } else {
            $db_error = "Session Error: User ID not found in session.";
        }
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

      <?php if ($db_error): ?>
        <div class="alert alert-danger mb-4"><?= htmlspecialchars($db_error) ?></div>
      <?php endif; ?>

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
      <div class="card border-<?= $result['color'] ?> mb-3">
        <div class="card-body">
          <h5>Verdict: <span class="badge bg-<?= $result['color'] ?>"><?= $result['label'] ?></span></h5>
          <p>Risk Score: <strong><?= $score ?>/100</strong></p>
          <?php if ($flags): ?>
            <h6>Red Flags (Rule-Based Detection):</h6>
            <ul><?php foreach ($flags as $f): ?><li><?= htmlspecialchars($f) ?></li><?php endforeach; ?></ul>
          <?php else: ?>
            <p class="text-success mb-0">No obvious phishing indicators or suspicious links detected.</p>
          <?php endif; ?>
        </div>
      </div>
      <?php endif; ?>

      <?php if ($ai_assessment): ?>
      <div class="card border-info mb-3">
        <div class="card-body">
          <h6 class="text-info mb-2">🤖 AI Assessment (Groq — second opinion)</h6>
          <p class="mb-1">AI risk score: <strong><?= $ai_assessment['score'] ?>/100</strong></p>
          <p class="text-muted small mb-0"><?= htmlspecialchars($ai_assessment['reasoning']) ?></p>
        </div>
      </div>
      <?php endif; ?>

      <?php if ($api_notes): ?>
      <div class="card border-secondary">
        <div class="card-body">
          <h6 class="text-muted mb-2">External checks not applied to this scan:</h6>
          <ul class="text-muted small mb-0">
            <?php foreach ($api_notes as $n): ?><li><?= htmlspecialchars($n) ?></li><?php endforeach; ?>
          </ul>
        </div>
      </div>
      <?php endif; ?>

    </div>
  </div>
</div>
</body>
</html>