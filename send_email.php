<?php
require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/db.php';

requireAdmin();

/**
 * Send one email via Brevo's HTTP API (port 443 — works even where SMTP ports are blocked).
 * Returns ['success' => bool, 'error' => ?string]
 */
function sendViaBrevo(string $apiKey, string $fromEmail, string $fromName, string $toEmail, string $toName, string $subject, string $htmlBody): array
{
    $payload = json_encode([
        'sender'      => ['email' => $fromEmail, 'name' => $fromName],
        'to'          => [['email' => $toEmail, 'name' => $toName]],
        'subject'     => $subject,
        'htmlContent' => $htmlBody,
    ]);

    $ch = curl_init('https://api.brevo.com/v3/smtp/email');
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 10,
        CURLOPT_CONNECTTIMEOUT => 5,
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => $payload,
        CURLOPT_HTTPHEADER     => [
            "api-key: {$apiKey}",
            "Content-Type: application/json",
            "Accept: application/json",
        ],
    ]);
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curlErr  = curl_error($ch);
    curl_close($ch);

    if ($curlErr) {
        return ['success' => false, 'error' => "Connection failed: {$curlErr}"];
    }
    if ($httpCode >= 200 && $httpCode < 300) {
        return ['success' => true, 'error' => null];
    }

    $data = json_decode($response, true);
    $msg  = $data['message'] ?? "Brevo returned HTTP {$httpCode}";
    return ['success' => false, 'error' => $msg];
}

$error = '';
$success = '';

$employees = $pdo->query("SELECT id, name, email, department FROM employees ORDER BY name")->fetchAll();
$campaigns = $pdo->query("SELECT id, campaign_name FROM campaigns ORDER BY sent_at DESC")->fetchAll();
$smtp = $pdo->query("SELECT * FROM smtp_settings ORDER BY id DESC LIMIT 1")->fetch();
$templates = $pdo->query("SELECT * FROM email_templates ORDER BY template_name")->fetchAll();

$brevoApiKey = $smtp['brevo_api_key'] ?? '';

if (!$smtp || empty($smtp['from_email']) || empty($brevoApiKey)) {
    $error = 'Email sending isn\'t set up yet. Please add your Brevo API key and From Email in Settings.';
}
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $campaign_id = filter_input(INPUT_POST, 'campaign_id', FILTER_VALIDATE_INT);
    $employee_ids = $_POST['employee_ids'] ?? [];
    $subject = trim($_POST['subject'] ?? '');
    $message = trim($_POST['message'] ?? '');
    $link_text = trim($_POST['link_text'] ?? '') ?: 'Verify Account →';
    $save_template_name = trim($_POST['save_template_name'] ?? '');

    if ($save_template_name !== '' && $subject !== '' && $message !== '') {
        if (mb_strlen($save_template_name) > 191) {
            $error = 'Template name is too long (max 191 characters). Please shorten it.';
        } else {
            try {
                $stmt = $pdo->prepare("INSERT INTO email_templates (template_name, subject, message, link_text) VALUES (:n, :s, :m, :l)");
                $stmt->execute([':n' => $save_template_name, ':s' => $subject, ':m' => $message, ':l' => $link_text]);
                $templates = $pdo->query("SELECT * FROM email_templates ORDER BY template_name")->fetchAll();
            } catch (PDOException $e) {
                $error = 'Could not save template — please check your inputs and try again.';
            }
        }
    }

    if ($error) {
        // Sender/API key missing — already set above, don't overwrite it.
    } elseif (!$campaign_id || empty($employee_ids) || $subject === '' || $message === '') {
        $error = 'Pick a campaign, at least one employee, and fill in the subject and message.';
    } else {
        $baseUrl = (isset($_SERVER['HTTPS']) ? 'https://' : 'http://') . $_SERVER['HTTP_HOST'] . dirname($_SERVER['PHP_SELF']);
        $sentCount = 0;

        foreach ($employee_ids as $eid) {
            $eid = (int) $eid;
            $stmt = $pdo->prepare("SELECT * FROM employees WHERE id = :id");
            $stmt->execute([':id' => $eid]);
            $employee = $stmt->fetch();
            if (!$employee) continue;

            $token = bin2hex(random_bytes(16));

            // Log the "sent" event with the token attached
            $stmt = $pdo->prepare(
                "INSERT INTO tracking_logs (campaign_id, employee_id, action_type, token) VALUES (:cid, :eid, 'sent', :token)"
            );
            $stmt->execute([':cid' => $campaign_id, ':eid' => $eid, ':token' => $token]);

            $link = $baseUrl . '/index.php?t=' . $token;

            $personalizedMessage = str_replace('{name}', $employee['name'], $message);
            $htmlBody = nl2br(htmlspecialchars($personalizedMessage)) . "<br><br><a href='{$link}' style='display:inline-block;padding:10px 20px;background:#2F4B9E;color:#fff;text-decoration:none;border-radius:6px;'>" . htmlspecialchars($link_text) . "</a>";

            $sendResult = sendViaBrevo(
                $brevoApiKey,
                $smtp['from_email'],
                $smtp['from_name'] ?: 'IT Support',
                $employee['email'],
                $employee['name'],
                $subject,
                $htmlBody
            );

            if ($sendResult['success']) {
                $sentCount++;
            } else {
                $error .= "Failed to email {$employee['email']}: {$sendResult['error']}. ";
            }
        }

        if ($sentCount > 0) {
            $success = "Sent to {$sentCount} employee(s).";
        }
    }
}
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>PhishShield — Send Campaign</title>
    <link href="assets/phishshield.css" rel="stylesheet">
    <link rel="icon" href="favicon.svg" type="image/svg+xml">
<link rel="alternate icon" href="favicon.ico">
<link rel="apple-touch-icon" href="favicon-180.png">
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

<div class="ps-shell-narrow ps-page">
    <h1 style="font-size:24px;">Send a phishing simulation campaign</h1>
    <p style="margin-bottom:20px;">Each selected employee gets their own tracking link so clicks and submissions can be attributed individually.</p>

    <?php if ($error): ?><div class="ps-alert ps-alert-danger"><?= htmlspecialchars($error) ?></div><?php endif; ?>
    <?php if ($success): ?><div class="ps-alert ps-alert-success"><?= htmlspecialchars($success) ?></div><?php endif; ?>

    <?php if (!$smtp || empty($smtp['from_email'])): ?>
        <a href="settings.php" class="ps-btn ps-btn-admin" style="margin-bottom:20px;">Set up email sending →</a>
    <?php endif; ?>

    <div class="ps-card">
      <div class="ps-card-body">
        <form method="post" id="campaignForm">
            <?php if ($templates): ?>
                <div class="ps-field">
                    <label class="ps-label">Load a saved template <span style="font-weight:400;color:var(--faint);">(optional)</span></label>
                    <select id="templateLoader" class="ps-select">
                        <option value="">-- Start blank --</option>
                        <?php foreach ($templates as $t): ?>
                            <option value="<?= $t['id'] ?>"><?= htmlspecialchars($t['template_name']) ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
            <?php endif; ?>
            <div class="ps-field">
                <label class="ps-label">Campaign</label>
                <select name="campaign_id" class="ps-select" required>
                    <?php foreach ($campaigns as $c): ?>
                        <option value="<?= $c['id'] ?>"><?= htmlspecialchars($c['campaign_name']) ?></option>
                    <?php endforeach; ?>
                </select>
            </div>
            <div class="ps-field">
                <label class="ps-label">Email subject</label>
                <input type="text" id="subject" name="subject" class="ps-input" placeholder="e.g. Unusual activity on your account" value="<?= htmlspecialchars($_POST['subject'] ?? '') ?>" required>
            </div>
            <div class="ps-field">
                <label class="ps-label">Email message</label>
                <textarea id="message" name="message" rows="5" class="ps-textarea" placeholder="Write the message. Use {name} to insert the employee's name automatically." required><?= htmlspecialchars($_POST['message'] ?? '') ?></textarea>
                <p class="ps-hint">Tip: type {name} anywhere and it'll be replaced with each employee's real name.</p>
            </div>
            <div class="ps-field">
                <label class="ps-label">Button text</label>
                <input type="text" id="link_text" name="link_text" class="ps-input" placeholder="e.g. Verify Account, Reset Password, Click Here" value="<?= htmlspecialchars($_POST['link_text'] ?? '') ?>">
                <p class="ps-hint">This is the clickable button text in the email. Leave blank to use "Verify Account →".</p>
            </div>
            <div class="ps-field">
                <label class="ps-label">Save this as a new template <span style="font-weight:400;color:var(--faint);">(optional)</span></label>
                <input type="text" name="save_template_name" class="ps-input" maxlength="191" placeholder="e.g. Fake IT Support Alert">
                <p class="ps-hint">If you type a name here, this subject/message/button combo gets saved for reuse next time.</p>
            </div>

            <div class="ps-field">
                <label class="ps-label">Employees</label>
                <div class="ps-card" style="box-shadow:none;">
                  <div class="ps-card-body" style="padding:14px 18px;max-height:260px;overflow-y:auto;">
                    <?php foreach ($employees as $e): ?>
                        <div class="ps-check" style="margin-bottom:8px;">
                            <input type="checkbox" name="employee_ids[]" value="<?= $e['id'] ?>" id="emp<?= $e['id'] ?>">
                            <label for="emp<?= $e['id'] ?>"><?= htmlspecialchars($e['name']) ?> <span class="ps-small">(<?= htmlspecialchars($e['email']) ?>)</span></label>
                        </div>
                    <?php endforeach; ?>
                  </div>
                </div>
            </div>
            <button type="submit" class="ps-btn ps-btn-admin">Send campaign emails</button>
        </form>
      </div>
    </div>
</div>

<?php if ($templates): ?>
<script>
    const templates = <?= json_encode($templates) ?>;
    document.getElementById('templateLoader').addEventListener('change', function() {
        const chosen = templates.find(t => t.id == this.value);
        if (chosen) {
            document.getElementById('subject').value = chosen.subject;
            document.getElementById('message').value = chosen.message;
            document.getElementById('link_text').value = chosen.link_text;
        } else {
            document.getElementById('subject').value = '';
            document.getElementById('message').value = '';
            document.getElementById('link_text').value = '';
        }
    });
</script>
<?php endif; ?>
</body>
</html>