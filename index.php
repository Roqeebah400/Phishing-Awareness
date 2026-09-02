<?php
// index.php — Site entry point.
// No tracking params  -> shows the real PhishShield marketing homepage.
// ?cid=&eid= present  -> this is a campaign tracking link, shows the
//                        simulated phishing sign-in page and logs the event.
require_once __DIR__ . '/db.php';

// Edit this to match your organization's name/branding for the simulation page.
$companyName = 'Atlas Workspace';

function logTrackingEvent(PDO $pdo, string $action, ?int $cid, ?int $eid, array $meta = []): void {
    try {
        $stmt = $pdo->prepare(
            "INSERT INTO tracking_logs (campaign_id, employee_id, action, ip, user_agent, meta)
             VALUES (:cid, :eid, :action, :ip, :ua, :meta)"
        );
        $stmt->execute([
            ':cid'    => $cid ?: null,
            ':eid'    => $eid ?: null,
            ':action' => $action,
            ':ip'     => $_SERVER['REMOTE_ADDR'] ?? null,
            ':ua'     => $_SERVER['HTTP_USER_AGENT'] ?? null,
            ':meta'   => json_encode($meta),
        ]);
    } catch (\Exception $e) {
        // Never let a logging failure break the page for the visitor
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Simulated credential submission from the phishing landing page.
    // IMPORTANT: we NEVER store the actual password — only that a submission happened.
    $cid = filter_input(INPUT_POST, 'cid', FILTER_VALIDATE_INT) ?: null;
    $eid = filter_input(INPUT_POST, 'eid', FILTER_VALIDATE_INT) ?: null;
    $submittedUsername = trim($_POST['username'] ?? '');

    logTrackingEvent($pdo, 'submitted_data', $cid, $eid, [
        'username_length' => strlen($submittedUsername),
        'had_password'    => isset($_POST['password']) && $_POST['password'] !== '',
    ]);

    header('Location: training.php' . ($eid ? '?eid=' . $eid : ''));
    exit;
}

$cid = filter_input(INPUT_GET, 'cid', FILTER_VALIDATE_INT) ?: null;
$eid = filter_input(INPUT_GET, 'eid', FILTER_VALIDATE_INT) ?: null;

if ($cid || $eid) {
    // Real tracking link → log the click and show the simulated sign-in page
    logTrackingEvent($pdo, 'clicked', $cid, $eid);
    renderPhishingLanding($companyName, $cid, $eid);
    exit;
}

// Otherwise → this is just a normal visitor. Show the real homepage.
renderHomepage();
exit;

// ---------------------------------------------------------------------
function renderHomepage(): void {
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PhishShield — Phishing awareness that sticks</title>
<style>
  :root{
    --canvas:#F7F9FD;
    --canvas-alt:#EEF2FB;
    --ink:#101828;
    --muted:#5B6472;
    --blue:#1D4ED8;
    --blue-deep:#153FAE;
    --blue-bright:#3B7CFF;
    --accent:#2F6BFF;
    --accent-hover:#1D4ED8;
    --border:#E2E7F5;
    --danger:#DC3F3F;
  }
  *{box-sizing:border-box;}
  html{scroll-behavior:smooth;}
  body{
    margin:0;
    background:var(--canvas);
    color:var(--ink);
    font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
    line-height:1.5;
    overflow-x:hidden;
  }
  h1,h2,h3{
    font-family:ui-serif,Georgia,"Iowan Old Style",serif;
    font-weight:600;
    letter-spacing:-0.01em;
    margin:0;
  }
  a{ color:inherit; }
  .wrap{
    max-width:1120px;
    margin:0 auto;
    padding:0 32px;
    position:relative;
  }

  /* Reveal-on-scroll */
  .reveal{
    opacity:0;
    transform:translateY(18px);
    transition:opacity .6s ease, transform .6s ease;
  }
  .reveal.is-visible{
    opacity:1;
    transform:translateY(0);
  }
  @media (prefers-reduced-motion: reduce){
    html{ scroll-behavior:auto; }
    .reveal{ opacity:1; transform:none; transition:none; }
    *{ animation-duration:0.001ms !important; animation-iteration-count:1 !important; }
  }

  /* Nav */
  .nav-outer{
    position:sticky;
    top:0;
    z-index:40;
    background:rgba(247,249,253,0.72);
    backdrop-filter:blur(10px);
    -webkit-backdrop-filter:blur(10px);
    border-bottom:1px solid transparent;
    transition:border-color .25s ease, box-shadow .25s ease;
  }
  .nav-outer.scrolled{
    border-bottom-color:var(--border);
    box-shadow:0 8px 24px -20px rgba(29,78,216,0.35);
  }
  .nav{
    display:flex;
    align-items:center;
    justify-content:space-between;
    padding:18px 0;
  }
  .nav-mark{
    display:flex;
    align-items:center;
    gap:10px;
    font-weight:600;
    font-size:17px;
  }
  .nav-glyph{
    width:26px; height:26px;
    border-radius:7px;
    background:linear-gradient(150deg,var(--blue-bright),var(--blue-deep));
    position:relative;
    flex-shrink:0;
    box-shadow:0 4px 12px -4px rgba(29,78,216,0.55);
  }
  .nav-glyph::after{
    content:"";
    position:absolute;
    inset:7px;
    border:1.5px solid rgba(255,255,255,0.85);
    border-radius:3px;
  }
  .nav-links{
    display:flex;
    align-items:center;
    gap:28px;
    font-size:14px;
  }
  .nav-links a{ text-decoration:none; color:var(--muted); position:relative; }
  .nav-links a::after{
    content:"";
    position:absolute;
    left:0; right:0; bottom:-4px;
    height:2px;
    background:var(--accent);
    transform:scaleX(0);
    transform-origin:left;
    transition:transform .2s ease;
  }
  .nav-links a:hover{ color:var(--ink); }
  .nav-links a:hover::after{ transform:scaleX(1); }

  .btn{
    display:inline-flex;
    align-items:center;
    justify-content:center;
    padding:10px 20px;
    border-radius:8px;
    font-size:14px;
    font-weight:600;
    text-decoration:none;
    border:1px solid transparent;
    cursor:pointer;
    transition:transform .15s ease, box-shadow .15s ease, background .15s ease, border-color .15s ease;
  }
  .btn-primary{
    background:linear-gradient(135deg,var(--blue-bright),var(--blue));
    color:#fff;
    box-shadow:0 8px 20px -8px rgba(29,78,216,0.55);
  }
  .btn-primary:hover{ transform:translateY(-1px); box-shadow:0 12px 24px -8px rgba(29,78,216,0.6); }
  .btn-ghost{
    border-color:var(--border);
    color:var(--ink);
    background:#fff;
  }
  .btn-ghost:hover{ border-color:var(--blue); transform:translateY(-1px); }

  /* Hero */
  .hero-outer{
    position:relative;
    overflow:hidden;
  }
  .hero-glow{
    position:absolute;
    top:-220px;
    right:-160px;
    width:640px;
    height:640px;
    border-radius:50%;
    background:radial-gradient(circle at 35% 35%, rgba(59,124,255,0.35), rgba(59,124,255,0) 70%);
    filter:blur(10px);
    animation:drift 16s ease-in-out infinite alternate;
    pointer-events:none;
  }
  .hero-glow-2{
    position:absolute;
    bottom:-200px;
    left:-180px;
    width:480px;
    height:480px;
    border-radius:50%;
    background:radial-gradient(circle at 60% 40%, rgba(29,78,216,0.18), rgba(29,78,216,0) 70%);
    filter:blur(10px);
    animation:drift 20s ease-in-out infinite alternate-reverse;
    pointer-events:none;
  }
  @keyframes drift{
    from{ transform:translate(0,0); }
    to{ transform:translate(-30px,30px); }
  }
  .hero{
    padding:72px 0 92px;
    display:grid;
    grid-template-columns:1.05fr 0.95fr;
    gap:56px;
    align-items:center;
    position:relative;
  }
  .hero h1{
    font-size:46px;
    line-height:1.16;
    max-width:520px;
    opacity:0;
    transform:translateY(16px);
    animation:rise .7s ease forwards;
    animation-delay:.05s;
  }
  .hero p.lead{
    font-family:inherit;
    font-size:17px;
    color:var(--muted);
    max-width:460px;
    margin:20px 0 30px;
    opacity:0;
    transform:translateY(16px);
    animation:rise .7s ease forwards;
    animation-delay:.2s;
  }
  .hero-ctas{
    display:flex;
    gap:12px;
    margin-bottom:14px;
    opacity:0;
    transform:translateY(16px);
    animation:rise .7s ease forwards;
    animation-delay:.34s;
  }
  .hero-note{
    font-size:13px;
    color:var(--muted);
    opacity:0;
    transform:translateY(16px);
    animation:rise .7s ease forwards;
    animation-delay:.46s;
  }
  @keyframes rise{
    to{ opacity:1; transform:translateY(0); }
  }
  @media (prefers-reduced-motion: reduce){
    .hero h1,.hero p.lead,.hero-ctas,.hero-note{ animation:none; opacity:1; transform:none; }
    .hero-glow,.hero-glow-2{ animation:none; }
  }

  /* Email mockup */
  .mock{
    background:#fff;
    border:1px solid var(--border);
    border-radius:14px;
    box-shadow:0 30px 60px -30px rgba(29,78,216,0.4);
    overflow:hidden;
    opacity:0;
    transform:translateY(20px) scale(.98);
    animation:rise-scale .7s ease forwards;
    animation-delay:.28s;
  }
  @keyframes rise-scale{
    to{ opacity:1; transform:translateY(0) scale(1); }
  }
  @media (prefers-reduced-motion: reduce){
    .mock{ animation:none; opacity:1; transform:none; }
  }
  .mock-head{
    padding:14px 18px;
    border-bottom:1px solid var(--border);
    display:flex;
    align-items:center;
    justify-content:space-between;
    font-size:12px;
    color:var(--muted);
    background:var(--canvas-alt);
  }
  .mock-dot{ display:inline-flex; gap:6px; }
  .mock-dot span{ width:8px; height:8px; border-radius:50%; background:#D4DDF3; }
  .mock-body{ padding:20px 20px 22px; }
  .mock-from{ font-size:13px; color:var(--muted); margin-bottom:4px; }
  .mock-from strong{ color:var(--ink); }
  .mock-subject{ font-size:15px; font-weight:600; margin-bottom:14px; }
  .mock-line{ font-size:13.5px; color:#3B4458; margin-bottom:10px; }
  .flag{
    background:#FDECEA;
    color:var(--danger);
    border-radius:4px;
    padding:0 4px;
    font-weight:600;
  }
  .mock-btn{
    display:inline-block;
    margin-top:6px;
    padding:8px 16px;
    background:var(--canvas-alt);
    border:1px dashed #B9C4E0;
    border-radius:6px;
    font-size:12.5px;
    color:var(--muted);
  }
  .mock-flags{
    margin-top:18px;
    padding-top:16px;
    border-top:1px solid var(--border);
  }
  .mock-flags-title{ font-size:11.5px; color:var(--muted); margin-bottom:8px; }
  .mock-flag-row{
    display:flex; align-items:center; gap:8px;
    font-size:12.5px; color:var(--ink); margin-bottom:7px;
  }
  .mock-flag-dot{ width:6px; height:6px; border-radius:50%; background:var(--danger); flex-shrink:0; }
  .mock-score{
    margin-top:14px;
    display:flex; align-items:center; justify-content:space-between;
    font-size:12.5px;
  }
  .mock-score b{ color:var(--danger); font-size:14px; }

  /* Stats */
  .stats{
    border-top:1px solid var(--border);
    border-bottom:1px solid var(--border);
    padding:36px 0;
    display:grid;
    grid-template-columns:repeat(4,1fr);
    gap:24px;
  }
  .stat b{
    font-family:ui-serif,Georgia,serif;
    display:block;
    font-size:28px;
    margin-bottom:4px;
    background:linear-gradient(135deg,var(--blue-deep),var(--blue-bright));
    -webkit-background-clip:text;
    background-clip:text;
    color:transparent;
  }
  .stat span{ font-size:13px; color:var(--muted); }

  /* Features */
  .section{ padding:88px 0; }
  .section-head{ max-width:560px; margin-bottom:44px; }
  .section-head h2{ font-size:30px; margin-bottom:12px; }
  .section-head p{ color:var(--muted); font-size:15.5px; }

  .features{
    display:grid;
    grid-template-columns:repeat(3,1fr);
    gap:1px;
    background:var(--border);
    border:1px solid var(--border);
    border-radius:14px;
    overflow:hidden;
  }
  .feature{
    background:#fff;
    padding:30px 26px;
    transition:transform .2s ease, box-shadow .2s ease;
    position:relative;
  }
  .feature:hover{
    transform:translateY(-3px);
    box-shadow:0 20px 40px -28px rgba(29,78,216,0.45);
    z-index:1;
  }
  .feature h3{ font-size:17px; margin-bottom:10px; }
  .feature p{ font-size:14px; color:var(--muted); margin:0; }
  .feature-mark{
    width:36px; height:36px;
    border-radius:9px;
    background:var(--canvas-alt);
    border:1px solid var(--border);
    margin-bottom:16px;
    position:relative;
  }
  .feature-mark::after{
    content:"";
    position:absolute;
    inset:10px;
    border-radius:4px;
    background:linear-gradient(135deg,var(--blue-bright),var(--blue));
  }

  /* How it works */
  .steps{
    background:linear-gradient(155deg,var(--blue-deep),var(--blue) 60%,#2A57C9);
    border-radius:18px;
    padding:52px 48px;
    color:#EAF0FF;
    position:relative;
    overflow:hidden;
  }
  .steps::after{
    content:"";
    position:absolute;
    right:-100px; top:-100px;
    width:300px; height:300px;
    border-radius:50%;
    border:1px solid rgba(255,255,255,0.12);
  }
  .steps h2{ color:#fff; font-size:26px; margin-bottom:36px; }
  .step-grid{ display:grid; grid-template-columns:repeat(3,1fr); gap:32px; position:relative; }
  .step-num{
    font-family:ui-serif,Georgia,serif;
    font-size:14px;
    color:#9FC0FF;
    margin-bottom:10px;
  }
  .step h4{ font-family:inherit; font-size:15.5px; font-weight:600; margin-bottom:8px; color:#fff; }
  .step p{ font-size:13.5px; color:#C4D6FA; margin:0; }

  /* CTA band */
  .cta-band{
    text-align:left;
    padding:64px 0;
    display:flex;
    align-items:center;
    justify-content:space-between;
    gap:24px;
    border-top:1px solid var(--border);
  }
  .cta-band h2{ font-size:26px; max-width:420px; }
  .cta-band-actions{ display:flex; gap:12px; flex-shrink:0; }

  /* Footer */
  footer{
    border-top:1px solid var(--border);
    padding:28px 0;
    display:flex;
    align-items:center;
    justify-content:space-between;
    font-size:13px;
    color:var(--muted);
  }
  footer a{ text-decoration:none; color:var(--muted); margin-left:18px; }
  footer a:hover{ color:var(--blue); }

  @media (max-width:860px){
    .hero{ grid-template-columns:1fr; padding:40px 0 56px; }
    .hero h1{ font-size:32px; max-width:none; }
    .stats{ grid-template-columns:repeat(2,1fr); }
    .features{ grid-template-columns:1fr; }
    .step-grid{ grid-template-columns:1fr; gap:24px; }
    .steps{ padding:36px 24px; }
    .cta-band{ flex-direction:column; align-items:flex-start; }
    .nav-links{ display:none; }
    .hero-glow,.hero-glow-2{ display:none; }
  }
</style>
</head>
<body>
<div class="nav-outer" id="navOuter">
  <div class="wrap">
    <nav class="nav">
      <div class="nav-mark"><span class="nav-glyph"></span>PhishShield</div>
      <div class="nav-links">
        <a href="#features">Features</a>
        <a href="#how-it-works">How it works</a>
      </div>
      <div style="display:flex;gap:10px;">
        <a href="signup.php" class="btn btn-ghost">Sign up</a>
        <a href="login.php" class="btn btn-primary">Sign in</a>
      </div>
    </nav>
  </div>
</div>

<div class="hero-outer">
  <div class="hero-glow"></div>
  <div class="hero-glow-2"></div>
  <div class="wrap">
    <section class="hero">
      <div>
        <h1>See who would click — before someone really does.</h1>
        <p class="lead">Run safe, simulated phishing campaigns for your team, then give every employee a checker they can use the moment something looks off in their inbox.</p>
        <div class="hero-ctas">
          <a href="signup.php" class="btn btn-primary">Sign up</a>
          <a href="login.php" class="btn btn-ghost">Sign in</a>
        </div>
        <p class="hero-note">Self-hosted. No real credentials are ever stored during a simulation.</p>
      </div>

      <div class="mock">
        <div class="mock-head">
          <span>Inbox — Suspicious email</span>
          <span class="mock-dot"><span></span><span></span><span></span></span>
        </div>
        <div class="mock-body">
          <div class="mock-from">From: <strong>it-support@accounts-secure.com</strong></div>
          <div class="mock-subject">Unusual activity on your account</div>
          <div class="mock-line">Your account has been <span class="flag">flagged for suspension</span>. Please <span class="flag">verify your account</span> immediately by confirming your <span class="flag">password</span> below.</div>
          <a class="mock-btn">Verify account →</a>
          <div class="mock-flags">
            <div class="mock-flags-title">Detector results</div>
            <div class="mock-flag-row"><span class="mock-flag-dot"></span>Urgency language detected</div>
            <div class="mock-flag-row"><span class="mock-flag-dot"></span>Sensitive data requested</div>
            <div class="mock-flag-row"><span class="mock-flag-dot"></span>Sender domain resembles a trusted brand</div>
            <div class="mock-score"><span>Risk score</span><b>82 / 100 — High risk</b></div>
          </div>
        </div>
      </div>
    </section>
  </div>
</div>

<div class="wrap">
  <div class="stats reveal">
    <div class="stat"><b>3</b><span>Steps to launch a campaign</span></div>
    <div class="stat"><b>0</b><span>Real passwords ever stored</span></div>
    <div class="stat"><b>100</b><span>Point risk score per email scanned</span></div>
    <div class="stat"><b>24/7</b><span>Detector available to staff</span></div>
  </div>

  <section class="section" id="features">
    <div class="section-head reveal">
      <h2>Everything you need to run a training exercise</h2>
      <p>From sending the simulation to reading the results, it's built around three simple parts.</p>
    </div>
    <div class="features reveal">
      <div class="feature">
        <div class="feature-mark"></div>
        <h3>Simulated campaigns</h3>
        <p>Add employees, create a campaign, and send a realistic test email with a unique tracking link for each person. Every click and submission is logged automatically.</p>
      </div>
      <div class="feature">
        <div class="feature-mark"></div>
        <h3>Email detector</h3>
        <p>Anyone on your team can paste a suspicious email and get an instant risk score — flagging urgency language, sensitive data requests, and spoofed senders.</p>
      </div>
      <div class="feature">
        <div class="feature-mark"></div>
        <h3>Risk dashboard</h3>
        <p>See scan history per employee and department-level trends, so you know exactly where more training is needed.</p>
      </div>
    </div>
  </section>

  <section class="section" id="how-it-works" style="padding-top:0;">
    <div class="steps reveal">
      <h2>How a campaign runs</h2>
      <div class="step-grid">
        <div class="step">
          <div class="step-num">01</div>
          <h4>Set up employees and a campaign</h4>
          <p>Add the people you're training and give the campaign a name.</p>
        </div>
        <div class="step">
          <div class="step-num">02</div>
          <h4>Send the simulated email</h4>
          <p>Each employee gets a realistic test message with their own tracking link.</p>
        </div>
        <div class="step">
          <div class="step-num">03</div>
          <h4>Review the results</h4>
          <p>Clicks and submissions land straight on your dashboard — no guesswork.</p>
        </div>
      </div>
    </div>
  </section>

  <div class="cta-band reveal">
    <h2>Ready to see where your team stands?</h2>
    <div class="cta-band-actions">
      <a href="signup.php" class="btn btn-primary">Sign up</a>
      <a href="login.php" class="btn btn-ghost">Sign in</a>
    </div>
  </div>

  <footer>
    <span>&copy; <?= date('Y') ?> PhishShield</span>
    <div>
      <a href="signup.php">Sign up</a>
      <a href="login.php">Sign in</a>
    </div>
  </footer>
</div>

<script>
  // Sticky nav shadow/blur once scrolled
  (function(){
    var navOuter = document.getElementById('navOuter');
    if (!navOuter) return;
    window.addEventListener('scroll', function(){
      if (window.scrollY > 8) navOuter.classList.add('scrolled');
      else navOuter.classList.remove('scrolled');
    }, { passive: true });
  })();

  // Scroll-reveal for sections below the fold
  (function(){
    var els = document.querySelectorAll('.reveal');
    if (!('IntersectionObserver' in window) || els.length === 0) {
      els.forEach(function(el){ el.classList.add('is-visible'); });
      return;
    }
    var io = new IntersectionObserver(function(entries){
      entries.forEach(function(entry){
        if (entry.isIntersecting) {
          entry.target.classList.add('is-visible');
          io.unobserve(entry.target);
        }
      });
    }, { threshold: 0.15 });
    els.forEach(function(el){ io.observe(el); });
  })();
</script>
</body>
</html>
<?php
}

// ---------------------------------------------------------------------
function renderPhishingLanding(string $companyName, ?int $cid, ?int $eid): void {
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign in — <?= htmlspecialchars($companyName) ?></title>
<style>
  :root{
    --panel:#101C34;
    --panel-line:#22335A;
    --canvas:#F5F6F8;
    --ink:#16213C;
    --muted:#5B6472;
    --border:#E1E4E9;
    --accent:#2F4B9E;
    --accent-hover:#25397A;
  }
  *{box-sizing:border-box;}
  html,body{height:100%;}
  body{
    margin:0;
    font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Inter,Roboto,sans-serif;
    color:var(--ink);
    background:var(--canvas);
  }
  .layout{
    min-height:100vh;
    display:grid;
    grid-template-columns:minmax(0,42%) minmax(0,58%);
  }
  .brand{
    background:var(--panel);
    color:#EDEFF5;
    padding:56px 48px;
    display:flex;
    flex-direction:column;
    justify-content:space-between;
    position:relative;
    overflow:hidden;
  }
  .brand::before{
    content:"";
    position:absolute;
    right:-120px;
    bottom:-120px;
    width:420px;
    height:420px;
    border-radius:50%;
    border:1px solid var(--panel-line);
  }
  .brand::after{
    content:"";
    position:absolute;
    right:-40px;
    bottom:-40px;
    width:280px;
    height:280px;
    border-radius:50%;
    border:1px solid var(--panel-line);
  }
  .mark{
    display:flex;
    align-items:center;
    gap:10px;
    font-size:19px;
    font-weight:600;
    letter-spacing:-0.01em;
  }
  .mark-glyph{
    width:26px;
    height:26px;
    border-radius:7px;
    background:linear-gradient(160deg,#4A6BD6,#2F4B9E);
    flex-shrink:0;
  }
  .brand-copy{
    max-width:340px;
    position:relative;
    z-index:1;
  }
  .brand-copy h1{
    font-size:28px;
    line-height:1.3;
    font-weight:600;
    letter-spacing:-0.01em;
    margin:0 0 12px;
  }
  .brand-copy p{
    font-size:15px;
    line-height:1.6;
    color:#B7BFD4;
    margin:0;
  }
  .brand-foot{
    font-size:13px;
    color:#7C87A6;
    position:relative;
    z-index:1;
  }
  .stage{
    display:flex;
    align-items:center;
    justify-content:center;
    padding:48px 24px;
  }
  .form-wrap{
    width:100%;
    max-width:360px;
  }
  .form-wrap h2{
    font-size:22px;
    font-weight:600;
    letter-spacing:-0.01em;
    margin:0 0 6px;
  }
  .form-wrap .sub{
    font-size:14px;
    color:var(--muted);
    margin:0 0 32px;
  }
  label{
    display:block;
    font-size:13px;
    font-weight:500;
    color:var(--ink);
    margin-bottom:6px;
  }
  .field{ margin-bottom:18px; }
  input[type="text"],
  input[type="password"]{
    width:100%;
    padding:11px 13px;
    font-size:15px;
    border:1px solid var(--border);
    border-radius:8px;
    background:#fff;
    color:var(--ink);
    transition:border-color .15s ease, box-shadow .15s ease;
  }
  input[type="text"]:focus,
  input[type="password"]:focus{
    outline:none;
    border-color:var(--accent);
    box-shadow:0 0 0 3px rgba(47,75,158,0.15);
  }
  .row-between{
    display:flex;
    justify-content:flex-end;
    margin:-10px 0 20px;
  }
  .row-between a{
    font-size:13px;
    color:var(--accent);
    text-decoration:none;
  }
  .row-between a:hover{ text-decoration:underline; }
  button{
    width:100%;
    padding:12px;
    font-size:15px;
    font-weight:600;
    color:#fff;
    background:var(--accent);
    border:none;
    border-radius:8px;
    cursor:pointer;
    transition:background .15s ease;
  }
  button:hover{ background:var(--accent-hover); }
  button:focus-visible{
    outline:none;
    box-shadow:0 0 0 3px rgba(47,75,158,0.3);
  }
  .divider{
    display:flex;
    align-items:center;
    gap:12px;
    margin:28px 0;
    color:var(--muted);
    font-size:12px;
  }
  .divider::before,
  .divider::after{
    content:"";
    flex:1;
    height:1px;
    background:var(--border);
  }
  .helper{
    text-align:center;
    font-size:13px;
    color:var(--muted);
  }
  @media (prefers-reduced-motion: reduce){ *{ transition:none !important; } }
  @media (max-width:840px){
    .layout{ grid-template-columns:1fr; }
    .brand{ padding:28px 24px; min-height:0; }
    .brand::before,.brand::after{ display:none; }
    .brand-copy{ display:none; }
    .brand-foot{ display:none; }
    .stage{ padding:40px 20px; }
  }
</style>
</head>
<body>
<div class="layout">
  <div class="brand">
    <div class="mark">
      <span class="mark-glyph"></span>
      <?= htmlspecialchars($companyName) ?>
    </div>
    <div class="brand-copy">
      <h1>One account for everything you work on.</h1>
      <p>Sign in to pick up where you left off across mail, files, and your team's shared workspace.</p>
    </div>
    <div class="brand-foot">&copy; <?= date('Y') ?> <?= htmlspecialchars($companyName) ?></div>
  </div>

  <div class="stage">
    <div class="form-wrap">
      <h2>Sign in</h2>
      <p class="sub">Enter your details to continue to your workspace.</p>

      <form method="post">
        <input type="hidden" name="cid" value="<?= htmlspecialchars((string)($cid ?? '')) ?>">
        <input type="hidden" name="eid" value="<?= htmlspecialchars((string)($eid ?? '')) ?>">

        <div class="field">
          <label for="username">Email or username</label>
          <input type="text" id="username" name="username" autocomplete="off" required>
        </div>

        <div class="field">
          <label for="password">Password</label>
          <input type="password" id="password" name="password" autocomplete="off" required>
        </div>

        <div class="row-between">
          <a href="#">Forgot password?</a>
        </div>

        <button type="submit">Sign in</button>
      </form>

      <div class="divider">or</div>
      <p class="helper">Having trouble signing in? Contact your IT team.</p>
    </div>
  </div>
</div>
</body>
</html>
<?php
}