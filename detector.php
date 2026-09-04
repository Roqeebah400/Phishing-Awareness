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

// Map internal color keywords to design-system accent classes
$colorMap = [
    'danger'  => ['card' => 'ps-result-danger',  'badge' => 'ps-badge-danger'],
    'warning' => ['card' => 'ps-result-warning', 'badge' => 'ps-badge-warn'],
    'success' => ['card' => 'ps-result-success', 'badge' => 'ps-badge-good'],
];
$resultClasses = $result ? $colorMap[$result['color']] : null;
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>PhishShield — Email Detector</title>
  <link href="assets/phishshield.css" rel="stylesheet">
  <style>
    .ps-score-ring{
      width:96px; height:96px;
      border-radius:50%;
      display:flex; align-items:center; justify-content:center;
      flex-direction:column;
      font-family:ui-serif,Georgia,serif;
      flex-shrink:0;
    }
    .ps-result-danger .ps-score-ring{ background:var(--danger-tint); color:var(--danger); border:2px solid #F3B6B0; }
    .ps-result-warning .ps-score-ring{ background:var(--warn-tint); color:var(--warn); border:2px solid #EAD097; }
    .ps-result-success .ps-score-ring{ background:var(--good-tint); color:var(--good); border:2px solid #A9E2C4; }
    .ps-score-ring b{ font-size:22px; line-height:1; }
    .ps-score-ring span{ font-size:10.5px; color:var(--muted); font-family:-apple-system,sans-serif; margin-top:2px; }
    .ps-result-head{ display:flex; align-items:center; gap:20px; }
    .ps-result-danger{ border-color:#F3B6B0; }
    .ps-result-warning{ border-color:#EAD097; }
    .ps-result-success{ border-color:#A9E2C4; }
  </style>
</head>
<body class="ps-body">

<nav class="ps-nav">
  <div class="ps-nav-inner">
    <div class="ps-brand"><span class="ps-brand-glyph"></span>PhishShield</div>
    <div class="ps-nav-actions">
      <span class="ps-nav-user">Welcome, <strong><?= htmlspecialchars($_SESSION['user_name'] ?? 'User') ?></strong></span>
      <a href="dashboard.php" class="ps-btn ps-btn-ghost ps-btn-sm">My dashboard</a>
      <a href="logout.php" class="ps-btn ps-btn-ghost ps-btn-sm">Logout</a>
    </div>
  </div>
</nav>

<div class="ps-shell-narrow ps-page">
  <h1 style="font-size:26px;">Scan a suspicious email</h1>
  <p style="margin-bottom:24px;">Paste the sender and message content below. We'll flag urgency language, spoofed domains, malicious links, and more.</p>

  <?php if ($db_error): ?>
    <div class="ps-alert ps-alert-danger"><?= htmlspecialchars($db_error) ?></div>
  <?php endif; ?>

  <div class="ps-card" style="margin-bottom:20px;">
    <div class="ps-card-body">
      <form method="post">
        <div class="ps-field">
          <label class="ps-label" for="sender">Sender email <span style="font-weight:400;color:var(--faint);">(optional)</span></label>
          <input type="text" id="sender" name="sender" class="ps-input" placeholder="e.g. support@company-secure.com" value="<?= htmlspecialchars($sender) ?>">
        </div>
        <div class="ps-field">
          <label class="ps-label" for="email_text">Email content</label>
          <textarea id="email_text" name="email_text" rows="8" class="ps-textarea" placeholder="Paste the full email text here…" required><?= htmlspecialchars($email_text) ?></textarea>
        </div>
        <button type="submit" class="ps-btn ps-btn-primary">Scan email</button>
      </form>
    </div>
  </div>

  <?php if ($result): ?>
  <div class="ps-card <?= $resultClasses['card'] ?>" style="margin-bottom:20px;">
    <div class="ps-card-body">
      <div class="ps-result-head" style="margin-bottom:18px;">
        <div class="ps-score-ring">
          <b><?= $score ?></b>
          <span>/ 100</span>
        </div>
        <div>
          <div class="ps-small" style="margin-bottom:4px;">Verdict</div>
          <span class="ps-badge <?= $resultClasses['badge'] ?>" style="font-size:13.5px;"><?= htmlspecialchars($result['label']) ?></span>
        </div>
      </div>

      <?php if ($flags): ?>
        <div class="ps-section-head" style="margin-top:8px;margin-bottom:10px;">
          <h3 style="font-size:15px;">Red flags found</h3>
        </div>
        <ul class="ps-flag-list">
          <?php foreach ($flags as $f): ?><li><?= htmlspecialchars($f) ?></li><?php endforeach; ?>
        </ul>
      <?php else: ?>
        <p style="color:var(--good);margin:0;">No obvious phishing indicators or suspicious links detected.</p>
      <?php endif; ?>
    </div>
  </div>
  <?php endif; ?>

  <?php if ($ai_assessment): ?>
  <div class="ps-card" style="margin-bottom:20px;border-left:3px solid var(--blue-bright);">
    <div class="ps-card-body">
      <h3 style="font-size:14.5px;color:var(--blue-deep);">AI assessment — second opinion</h3>
      <p style="margin-bottom:4px;">AI risk score: <strong style="color:var(--ink);"><?= $ai_assessment['score'] ?>/100</strong></p>
      <p class="ps-small" style="margin:0;"><?= htmlspecialchars($ai_assessment['reasoning']) ?></p>
    </div>
  </div>
  <?php endif; ?>

  <?php if ($api_notes): ?>
  <div class="ps-card">
    <div class="ps-card-body">
      <h3 style="font-size:13.5px;color:var(--muted);">External checks not applied to this scan</h3>
      <ul class="ps-flag-list ps-small">
        <?php foreach ($api_notes as $n): ?><li><?= htmlspecialchars($n) ?></li><?php endforeach; ?>
      </ul>
    </div>
  </div>
  <?php endif; ?>

</div>

</body>
</html>