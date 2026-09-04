<?php
require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/db.php';
requireUser();
// training.php - immediate teachable moment after a failed simulation
$eid = filter_input(INPUT_GET, 'eid', FILTER_VALIDATE_INT);
$cid = filter_input(INPUT_GET, 'cid', FILTER_VALIDATE_INT);

$template_type = null;
if ($cid) {
    $stmt = $pdo->prepare("SELECT template_type FROM campaigns WHERE id = :id");
    $stmt->execute([':id' => $cid]);
    $row = $stmt->fetch();
    if ($row) $template_type = $row['template_type'];
}

$lessons = [
    'HR_Memo' => [
        'title' => 'You Fell For a Fake HR Message',
        'tips' => [
            'Real HR announcements rarely ask you to "verify your account" or "confirm your password."',
            'Check if the sender email actually matches your company\'s real HR domain.',
            'HR communications about policy changes are usually sent to everyone, not as an urgent individual request.',
        ],
    ],
    'IT_Support' => [
        'title' => 'You Fell For a Fake IT Support Message',
        'tips' => [
            'Real IT support will never ask for your password over email — they already have admin access if needed.',
            '"Unusual activity" and "account suspended" messages are classic urgency tricks.',
            'When in doubt, contact IT directly through a known number or ticketing system — not by replying to the email.',
        ],
    ],
    'Invoice' => [
        'title' => 'You Fell For a Fake Invoice/Billing Message',
        'tips' => [
            'Unexpected invoices, especially urgent ones, are a common phishing tactic.',
            'Always verify with your finance/accounts team before clicking any "view invoice" link.',
            'Check the sender domain closely — attackers often use lookalike domains for billing scams.',
        ],
    ],
];

$default_lesson = [
    'title' => 'You Were Targeted — Quick Training',
    'tips' => [
        'Unexpected urgency or threats in the message.',
        'Sender domain doesn\'t match the organisation.',
        'Suspicious URL parameters or mismatched links.',
        'Requests for credentials on unusual pages.',
    ],
];

$lesson = $lessons[$template_type] ?? $default_lesson;
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Security Training — Teachable Moment</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>body{background:#f8f9fa}</style>
</head>
<body>
<div class="container py-5">
    <div class="card shadow-sm">
        <div class="card-body">
                        <h1 class="h3"><?= htmlspecialchars($lesson['title']) ?></h1>
            <p class="text-muted">Thanks for completing the check. This short lesson highlights what to watch for next time.</p>

            <h5 class="mt-4">Common Red Flags</h5>
            <ul>
                <?php foreach ($lesson['tips'] as $tip): ?>
                <li><?= htmlspecialchars($tip) ?></li>
                <?php endforeach; ?>
            </ul>

            <h5 class="mt-4">What We Logged</h5>
            <p class="small text-muted">We recorded that you attempted to submit data for the simulation. We do <strong>not</strong> store any submitted passwords or secrets — only the fact that a submission occurred and timing/context metadata.</p>

            <a href="detector.php<?= $eid ? '?eid='.$eid : '' ?>" class="btn btn-outline-danger mt-3">Try the Email Detector Now</a>
            <a href="dashboard.php" class="btn btn-primary mt-3">Return to Home</a>
        </div>
    </div>
</div>
</body>
</html>