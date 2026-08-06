<?php
// test_db.php — quick DB diagnostic. Open this in your browser to see connection and table status.
require_once __DIR__ . '/db.php';

header('Content-Type: text/plain; charset=utf-8');
echo "DB Diagnostic\n";
try {
    $tables = ['employees','campaigns','tracking_logs'];
    $missing = [];
    foreach ($tables as $t) {
        $stmt = $pdo->prepare("SHOW TABLES LIKE :t");
        $stmt->execute([':t'=>$t]);
        if (!$stmt->fetch()) $missing[] = $t;
    }
    if (count($missing) === 0) {
        echo "All expected tables present: " . implode(', ', $tables) . "\n";
        $c = $pdo->query("SELECT COUNT(*) FROM tracking_logs")->fetchColumn();
        echo "tracking_logs rows: " . (int)$c . "\n";
    } else {
        echo "Missing tables: " . implode(', ', $missing) . "\n";
    }
} catch (\Exception $e) {
    echo "Error: " . $e->getMessage() . "\n";
    echo "Check DB credentials and that the database 'phishing_sim' is imported.\n";
}

echo "\nQuick curl tests:\n";
echo "GET click test: curl -v 'http://localhost/phishing-sim/index.php?cid=1&eid=1'\n";
echo "POST submit test: curl -v -L -X POST -d 'cid=1&eid=1&username=a&password=b' http://localhost/phishing-sim/dashboard.php\n";

?>
