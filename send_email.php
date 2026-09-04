<?php
require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/db.php';
require __DIR__ . '/vendor/autoload.php';

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

requireAdmin();

$error = '';
$success = '';

$employees = $pdo->query("SELECT id, name, email, department FROM employees ORDER BY name")->fetchAll();
$campaigns = $pdo->query("SELECT id, campaign_name FROM campaigns ORDER BY sent_at DESC")->fetchAll();
$smtp = $pdo->query("SELECT * FROM smtp_settings ORDER BY id DESC LIMIT 1")->fetch();
$templates = $pdo->query("SELECT * FROM email_templates ORDER BY template_name")->fetchAll();
if (!$smtp) {
    $error = 'No email sending settings found. Please set up your SMTP settings first.';
}
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $campaign_id = filter_input(INPUT_POST, 'campaign_id', FILTER_VALIDATE_INT);
    $employee_ids = $_POST['employee_ids'] ?? [];
    $subject = trim($_POST['subject'] ?? '');
    $message = trim($_POST['message'] ?? '');
    $link_text = trim($_POST['link_text'] ?? '') ?: 'Verify Account →';
    $save_template_name = trim($_POST['save_template_name'] ?? '');

    if ($save_template_name !== '' && $subject !== '' && $message !== '') {
        $stmt = $pdo->prepare("INSERT INTO email_templates (template_name, subject, message, link_text) VALUES (:n, :s, :m, :l)");
        $stmt->execute([':n' => $save_template_name, ':s' => $subject, ':m' => $message, ':l' => $link_text]);
        $templates = $pdo->query("SELECT * FROM email_templates ORDER BY template_name")->fetchAll();
    }

    if (!$campaign_id || empty($employee_ids) || $subject === '' || $message === '') {
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

            $mail = new PHPMailer(true);
            try {
                $mail->isSMTP();
                $mail->Host = $smtp['smtp_host'];
                $mail->SMTPAuth = true;
                $mail->Username = $smtp['smtp_username'];
                $mail->Password = $smtp['smtp_password'];
                $mail->Port = (int) $smtp['smtp_port'];
                $mail->SMTPSecure = ((int)$smtp['smtp_port'] === 465)
                    ? PHPMailer::ENCRYPTION_SMTPS
                    : PHPMailer::ENCRYPTION_STARTTLS;
                $mail->Timeout = 10;
                $mail->SMTPKeepAlive = false;

                $mail->setFrom($smtp['from_email'], $smtp['from_name']);
                $mail->addAddress($employee['email'], $employee['name']);
                $mail->Subject = $subject;
                $mail->isHTML(true);
                $personalizedMessage = str_replace('{name}', $employee['name'], $message);
                $mail->Body = nl2br(htmlspecialchars($personalizedMessage)) . "<br><br><a href='{$link}' style='display:inline-block;padding:10px 20px;background:#2F4B9E;color:#fff;text-decoration:none;border-radius:6px;'>" . htmlspecialchars($link_text) . "</a>";
                $mail->send();
                $sentCount++;
            } catch (Exception $e) {
                $error .= "Failed to email {$employee['email']}: {$mail->ErrorInfo}. ";
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
    <title>PhishShield — Send Campaign</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>

<body class="bg-light">
    <nav class="navbar navbar-dark bg-danger px-4">
        <span class="navbar-brand">⚙️ Send Phishing Campaign</span>
        <a href="manage.php" class="btn btn-dark btn-sm">Back to Admin</a>
    </nav>
    <div class="container py-5">
        <?php if ($error): ?><div class="alert alert-danger"><?= htmlspecialchars($error) ?></div><?php endif; ?>
        <?php if ($success): ?><div class="alert alert-success"><?= htmlspecialchars($success) ?></div><?php endif; ?>

        <?php if (!$smtp): ?>
            <a href="settings.php" class="btn btn-warning mb-3">Set Up Email Sending →</a>
        <?php endif; ?>

        <form method="post">
            <form method="post" id="campaignForm">
                <?php if ($templates): ?>
                    <div class="mb-3">
                        <label class="form-label">Load a Saved Template (optional)</label>
                        <select id="templateLoader" class="form-select">
                            <option value="">-- Start blank --</option>
                            <?php foreach ($templates as $t): ?>
                                <option value="<?= $t['id'] ?>"><?= htmlspecialchars($t['template_name']) ?></option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                <?php endif; ?>
                <div class="mb-3">
                    <label class="form-label">Campaign</label>
                    <select name="campaign_id" class="form-select" required>
                        <?php foreach ($campaigns as $c): ?>
                            <option value="<?= $c['id'] ?>"><?= htmlspecialchars($c['campaign_name']) ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="mb-3">

                    <label class="form-label">Email Subject</label>
                    <input type="text" id="subject" name="subject" class="form-control" placeholder="e.g. Unusual activity on your account" value="<?= htmlspecialchars($_POST['subject'] ?? '') ?>" required>
                </div>
                <div class="mb-3">
                    <label class="form-label">Email Message</label>
                    <textarea id="message" name="message" rows="5" class="form-control" placeholder="Write the message. Use {name} to insert the employee's name automatically." required><?= htmlspecialchars($_POST['message'] ?? '') ?></textarea>
                    <small class="text-muted">Tip: type {name} anywhere and it'll be replaced with each employee's real name.</small>
                </div>
                <div class="mb-3">
                    <label class="form-label">Button Text</label>
                    <input type="text" id="link_text" name="link_text" class="form-control" placeholder="e.g. Verify Account, Reset Password, Click Here" value="<?= htmlspecialchars($_POST['link_text'] ?? '') ?>">
                    <small class="text-muted">This is the clickable button text in the email. Leave blank to use "Verify Account →".</small>
                </div>
                <div class="mb-3">
                    <label class="form-label">Save this as a new template (optional)</label>
                    <input type="text" name="save_template_name" class="form-control" placeholder="e.g. Fake IT Support Alert">
                    <small class="text-muted">If you type a name here, this subject/message/button combo gets saved for reuse next time.</small>
                </div>

                <div class="mb-3">
                    <label class="form-label">Employees</label>
                    <?php foreach ($employees as $e): ?>
                        <div class="form-check">
                            <input class="form-check-input" type="checkbox" name="employee_ids[]" value="<?= $e['id'] ?>" id="emp<?= $e['id'] ?>">
                            <label class="form-check-label" for="emp<?= $e['id'] ?>"><?= htmlspecialchars($e['name']) ?> (<?= htmlspecialchars($e['email']) ?>)</label>
                        </div>
                    <?php endforeach; ?>
                </div>
                <button type="submit" class="btn btn-danger">Send Campaign Emails</button>
            </form>
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