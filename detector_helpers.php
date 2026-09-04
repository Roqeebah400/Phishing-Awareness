<?php
// detector_helpers.php — External reputation & domain-age checks for detector.php
//
// Both functions fail SAFE: if the API key is missing, the network is down,
// the API rate-limits us, or the response is malformed, they return
// 'checked' => false with an 'error' message instead of throwing. Callers
// should only add score/flags when 'checked' is true — never penalise an
// email just because an external API was unreachable.

$__phishshield_config = require __DIR__ . '/config.php';

/**
 * Check a URL against VirusTotal's reputation database (API v3).
 * Returns ['checked' => bool, 'malicious' => int, 'suspicious' => int, 'error' => ?string]
 */
function checkUrlReputation(string $url): array
{
    global $__phishshield_config;
    $apiKey = $__phishshield_config['VT_API_KEY'] ?? '';

    $result = ['checked' => false, 'malicious' => 0, 'suspicious' => 0, 'error' => null];

    if (!$apiKey || $apiKey === 'PASTE_YOUR_VIRUSTOTAL_KEY_HERE') {
        $result['error'] = 'VirusTotal API key not configured';
        return $result;
    }

    // VT v3 identifies URLs by a base64url encoding of the URL itself, so we can
    // look up existing scan history without submitting first (submission is async
    // and wouldn't be ready in time for this request anyway).
    $urlId = rtrim(strtr(base64_encode($url), '+/', '-_'), '=');

    $ch = curl_init("https://www.virustotal.com/api/v3/urls/{$urlId}");
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 6,
        CURLOPT_CONNECTTIMEOUT => 4,
        CURLOPT_HTTPHEADER     => ["x-apikey: {$apiKey}"],
    ]);
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curlErr  = curl_error($ch);
    curl_close($ch);

    if ($curlErr) {
        $result['error'] = "VirusTotal request failed: {$curlErr}";
        return $result;
    }

    if ($httpCode === 404) {
        // URL has never been scanned by anyone before. Submit it in the
        // background for next time, but don't block this scan waiting on it.
        submitUrlToVirusTotal($url, $apiKey);
        $result['checked'] = true; // API call succeeded, there's just no history yet
        return $result;
    }

    if ($httpCode === 429) {
        $result['error'] = 'VirusTotal rate limit reached (free tier: ~4 req/min)';
        return $result;
    }

    if ($httpCode !== 200) {
        $result['error'] = "VirusTotal returned HTTP {$httpCode}";
        return $result;
    }

    $data  = json_decode($response, true);
    $stats = $data['data']['attributes']['last_analysis_stats'] ?? null;

    if (!$stats) {
        $result['error'] = 'VirusTotal response missing analysis stats';
        return $result;
    }

    $result['checked']    = true;
    $result['malicious']  = (int)($stats['malicious'] ?? 0);
    $result['suspicious'] = (int)($stats['suspicious'] ?? 0);
    return $result;
}

/**
 * Fire-and-forget submission of a new URL to VirusTotal for future scanning.
 * We deliberately don't wait for or use the result in the current request.
 */
function submitUrlToVirusTotal(string $url, string $apiKey): void
{
    $ch = curl_init("https://www.virustotal.com/api/v3/urls");
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 3,
        CURLOPT_CONNECTTIMEOUT => 2,
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => http_build_query(['url' => $url]),
        CURLOPT_HTTPHEADER     => [
            "x-apikey: {$apiKey}",
            "Content-Type: application/x-www-form-urlencoded",
        ],
    ]);
    curl_exec($ch);
    curl_close($ch);
}

/**
 * Check how recently a domain was registered via WHOIS (WhoisXML API).
 * Returns ['checked' => bool, 'age_days' => ?int, 'error' => ?string]
 */
function checkDomainAge(string $domain): array
{
    global $__phishshield_config;
    $apiKey = $__phishshield_config['WHOIS_API_KEY'] ?? '';

    $result = ['checked' => false, 'age_days' => null, 'error' => null];

    $domain = preg_replace('/^www\./i', '', strtolower(trim($domain)));
    if ($domain === '') {
        $result['error'] = 'No domain provided';
        return $result;
    }

    if (!$apiKey || $apiKey === 'PASTE_YOUR_WHOISXML_KEY_HERE') {
        $result['error'] = 'WHOIS API key not configured';
        return $result;
    }

    $endpoint = "https://www.whoisxmlapi.com/whoisserver/WhoisService"
              . "?apiKey=" . urlencode($apiKey)
              . "&domainName=" . urlencode($domain)
              . "&outputFormat=JSON";

    $ch = curl_init($endpoint);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 6,
        CURLOPT_CONNECTTIMEOUT => 4,
    ]);
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curlErr  = curl_error($ch);
    curl_close($ch);

    if ($curlErr) {
        $result['error'] = "WHOIS request failed: {$curlErr}";
        return $result;
    }
    if ($httpCode !== 200) {
        $result['error'] = "WHOIS API returned HTTP {$httpCode}";
        return $result;
    }

    $data = json_decode($response, true);
    $createdDate = $data['WhoisRecord']['createdDate']
        ?? $data['WhoisRecord']['registryData']['createdDate']
        ?? null;

    if (!$createdDate) {
        $result['error'] = 'WHOIS record missing creation date (may be a privacy-protected or unregistered domain)';
        return $result;
    }

    try {
        $created = new DateTime($createdDate);
        $now     = new DateTime();
        $result['checked']  = true;
        $result['age_days'] = $now->diff($created)->days;
    } catch (\Exception $e) {
        $result['error'] = 'Could not parse WHOIS creation date';
    }

    return $result;
}

/**
 * Pull the domain out of either a plain domain, an email address, or a URL.
 */
function extractDomain(string $input): string
{
    $input = trim($input);
    if ($input === '') return '';

    if (str_contains($input, '@')) {
        return trim(substr(strrchr($input, '@'), 1));
    }
    if (preg_match('#^https?://#i', $input)) {
        return (string)(parse_url($input, PHP_URL_HOST) ?? '');
    }
    return $input;
}

function checkWithGroqLLM(string $email_text, string $sender = ''): array
{
    global $__phishshield_config;
    $apiKey = $__phishshield_config['GROQ_API_KEY'] ?? '';

    $result = ['checked' => false, 'ai_score' => null, 'reasoning' => null, 'error' => null];

    if (!$apiKey || $apiKey === 'PASTE_YOUR_GROQ_KEY_HERE') {
        $result['error'] = 'Groq API key not configured';
        return $result;
    }

    $prompt = "You are a phishing detection assistant. Rate this email's phishing risk from 0 to 100 "
            . "(0 = completely safe, 100 = definitely phishing). Judge tone, intent, and manipulation "
            . "tactics that keyword-matching alone would miss. Respond with ONLY a JSON object, no other "
            . "text: {\"score\": <0-100>, \"reasoning\": \"<one sentence>\"}\n\n"
            . "Sender: " . ($sender ?: 'not provided') . "\n\nEmail content:\n" . $email_text;

    $payload = json_encode([
        'model'       => 'openai/gpt-oss-120b',
        'messages'    => [['role' => 'user', 'content' => $prompt]],
        'temperature' => 0.2,
        'max_tokens'  => 200,
    ]);

    $ch = curl_init('https://api.groq.com/openai/v1/chat/completions');
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 15,
        CURLOPT_CONNECTTIMEOUT => 5,
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => $payload,
        CURLOPT_HTTPHEADER     => ["Authorization: Bearer {$apiKey}", "Content-Type: application/json"],
    ]);
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curlErr  = curl_error($ch);
    curl_close($ch);

    if ($curlErr)        { $result['error'] = "Groq request failed: {$curlErr}"; return $result; }
    if ($httpCode === 429) { $result['error'] = 'Groq rate limit reached'; return $result; }
    if ($httpCode !== 200) { $result['error'] = "Groq returned HTTP {$httpCode}"; return $result; }

    $data    = json_decode($response, true);
    $content = $data['choices'][0]['message']['content'] ?? null;
    if (!$content) { $result['error'] = 'Groq response missing content'; return $result; }

    $clean  = trim(preg_replace('/```json|```/', '', $content));
    $parsed = json_decode($clean, true);
    if (!isset($parsed['score'])) { $result['error'] = 'Could not parse AI response as JSON'; return $result; }

    $result['checked']   = true;
    $result['ai_score']  = max(0, min(100, (int)$parsed['score']));
    $result['reasoning'] = $parsed['reasoning'] ?? '';
    return $result;
}