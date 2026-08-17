<?php
// training.php - immediate teachable moment after a failed simulation
$eid = filter_input(INPUT_GET, 'eid', FILTER_VALIDATE_INT);
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
            <h1 class="h3">You Were Targeted — Quick Training</h1>
            <p class="text-muted">Thanks for completing the check. This short lesson highlights what to watch for next time.</p>

            <h5 class="mt-4">Common Red Flags</h5>
            <ul>
                <li>Unexpected urgency or threats in the message.</li>
                <li>Sender domain doesn't match the organisation.</li>
                <li>Suspicious URL parameters or mismatched links.</li>
                <li>Requests for credentials on unusual pages.</li>
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