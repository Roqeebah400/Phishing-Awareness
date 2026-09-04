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
    <title>PhishShield — Security Training</title>
    <link href="assets/phishshield.css" rel="stylesheet">
    <style>
      .ps-training-shell{ max-width:640px; margin:0 auto; padding:56px 24px; }
      .ps-training-mark{
        width:44px;height:44px;border-radius:12px;
        background:linear-gradient(150deg,var(--blue-bright),var(--blue-deep));
        display:flex;align-items:center;justify-content:center;
        color:#fff;font-size:20px;margin-bottom:18px;
      }
    </style>
</head>
<body class="ps-body">
<div class="ps-training-shell">
  <div class="ps-card">
    <div class="ps-card-body" style="padding:36px 36px 32px;">
      <div class="ps-training-mark">🎯</div>
      <h1 style="font-size:24px;"><?= htmlspecialchars($lesson['title']) ?></h1>
      <p>Thanks for completing the check. This short lesson highlights what to watch for next time.</p>

      <hr class="ps-divider">

      <h3 style="font-size:15px;">Common red flags</h3>
      <ul class="ps-flag-list">
        <?php foreach ($lesson['tips'] as $tip): ?>
        <li><?= htmlspecialchars($tip) ?></li>
        <?php endforeach; ?>
      </ul>

      <hr class="ps-divider">

      <h3 style="font-size:15px;">What we logged</h3>
      <p class="ps-small" style="margin:0;">We recorded that you attempted to submit data for the simulation. We do <strong>not</strong> store any submitted passwords or secrets — only the fact that a submission occurred and timing/context metadata.</p>

      <div style="display:flex;gap:10px;margin-top:26px;flex-wrap:wrap;">
        <a href="detector.php<?= $eid ? '?eid='.$eid : '' ?>" class="ps-btn ps-btn-ghost">Try the email detector now</a>
        <a href="dashboard.php" class="ps-btn ps-btn-primary">Return to home</a>
      </div>
    </div>
  </div>
</div>
</body>
</html>