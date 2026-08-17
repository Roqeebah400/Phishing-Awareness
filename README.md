# PhishShield — Phishing Awareness & Simulation Tool

A self-hosted web application for small organizations to run safe, simulated phishing
campaigns and train staff to recognize real threats.

## Features
- Admin login (secure, password-hashed)
- Create employees and campaigns
- Generate unique tracking links per employee/campaign
- Send simulated phishing emails via SMTP
- Fake login landing page that logs clicks and submissions (no real credentials stored)
- Instant "teachable moment" training page after a simulated failure
- Phishing email detector tool — paste any email to check for red flags
- Admin dashboard with department-level risk analytics

## Requirements
- XAMPP (Apache + PHP 8+ + MySQL)
- Composer (for PHPMailer)
- A free Mailtrap.io account (or any SMTP provider) for sending test emails

## Installation
1. Install XAMPP, start Apache and MySQL from the Control Panel.
2. Copy this project folder into `C:\xampp\htdocs\phishing-sim`.
3. Open `http://localhost/phpmyadmin`, create the database by running `phishing_sim.sql`
   in the SQL tab.
4. In the project folder, run `composer require phpmailer/phpmailer`.
5. Copy `db.php` and confirm your DB credentials (defaults: host=localhost, db=phishing_sim, user=root, pass=empty).
6. Create your admin account: temporarily add `create_admin.php` (see below), visit it once
   in your browser, then delete the file.
7. Visit `http://localhost/phishing-sim/login.php` and log in.

## Usage
1. Log in at `/login.php`.
2. Go to **Manage** — add employees and create a campaign.
3. Go to **Send Email** — pick an employee/campaign and send the simulated phishing email
   (via Mailtrap sandbox, so nothing goes to a real inbox during testing).
4. When a target clicks the link and submits the fake form, it's logged and they're
   redirected to a training page, then invited to try the detector tool.
5. View results anytime on the **Dashboard**.

## Security Notes
- No real passwords are ever stored — only the fact that a submission occurred.
- Admin pages (`dashboard.php`, `manage.php`, `verify.php`, `send_email.php`) require login.
- This tool is strictly for internal, consented training exercises.