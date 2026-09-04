<?php
// config.php — API keys and external service configuration for PhishShield
//
// DO NOT commit real keys to version control. Prefer setting these as
// environment variables (VT_API_KEY, WHOIS_API_KEY) in your XAMPP/Apache
// environment or a local .env loader. The literal strings below are only
// a fallback for quick local testing.

return [
    'VT_API_KEY'    => getenv('VT_API_KEY') ?: '',
    'WHOIS_API_KEY' => getenv('WHOIS_API_KEY') ?: '',
    'GROQ_API_KEY'  => getenv('GROQ_API_KEY') ?: '',
    'BREVO_API_KEY' => getenv('BREVO_API_KEY') ?: '',
];