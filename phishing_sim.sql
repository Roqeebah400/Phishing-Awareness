-- phishing_sim.sql — PhishShield database schema
-- Matches the column names actually used across the PHP codebase
-- (campaign_name, template_type, action_type, token, ip_address, etc.)
-- Safe to run fresh: creates the database and all tables needed by the app.

CREATE DATABASE IF NOT EXISTS `phishing_sim` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE `phishing_sim`;

-- Admin + student/user accounts (login.php, admin_login.php, signup.php, admin_signup.php)
CREATE TABLE IF NOT EXISTS `users` (
  `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `name` VARCHAR(191) NOT NULL,
  `email` VARCHAR(191) NOT NULL UNIQUE,
  `password_hash` VARCHAR(255) NOT NULL,
  `role` ENUM('user','admin') NOT NULL DEFAULT 'user',
  `department` VARCHAR(100) DEFAULT 'Unassigned',
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Simulation targets (manage_employees.php, send_email.php)
CREATE TABLE IF NOT EXISTS `employees` (
  `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `name` VARCHAR(191) NOT NULL,
  `email` VARCHAR(191) NOT NULL UNIQUE,
  `department` VARCHAR(100) DEFAULT 'Unassigned',
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Campaigns. template_type drives which lesson training.php shows after a click.
CREATE TABLE IF NOT EXISTS `campaigns` (
  `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `campaign_name` VARCHAR(191) NOT NULL,
  `template_type` ENUM('HR_Memo','IT_Support','Invoice') DEFAULT NULL,
  `sent_at` DATETIME DEFAULT NULL,
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Every send/click/submit event. token is the per-recipient tracking link value.
CREATE TABLE IF NOT EXISTS `tracking_logs` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `campaign_id` INT UNSIGNED DEFAULT NULL,
  `employee_id` INT UNSIGNED DEFAULT NULL,
  `action_type` ENUM('sent','clicked','submitted_data') NOT NULL,
  `token` VARCHAR(64) DEFAULT NULL,
  `ip_address` VARCHAR(45) DEFAULT NULL,
  `user_agent` VARCHAR(512) DEFAULT NULL,
  `timestamp` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY (`campaign_id`),
  KEY (`employee_id`),
  KEY `idx_token` (`token`),
  CONSTRAINT `fk_tracking_campaign` FOREIGN KEY (`campaign_id`) REFERENCES `campaigns`(`id`) ON DELETE SET NULL,
  CONSTRAINT `fk_tracking_employee` FOREIGN KEY (`employee_id`) REFERENCES `employees`(`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Email detector scan history (detector.php, dashboard.php, manage.php)
CREATE TABLE IF NOT EXISTS `detector_checks` (
  `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id` INT UNSIGNED DEFAULT NULL,
  `input_content` TEXT NOT NULL,
  `risk_score` INT NOT NULL,
  `flags_count` INT NOT NULL,
  `verdict` VARCHAR(50) NOT NULL,
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY (`user_id`),
  CONSTRAINT `fk_detector_user` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Outbound mail settings (settings.php, send_email.php)
CREATE TABLE IF NOT EXISTS `smtp_settings` (
  `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `smtp_host` VARCHAR(191) NOT NULL,
  `smtp_port` INT UNSIGNED NOT NULL,
  `smtp_username` VARCHAR(191) NOT NULL,
  `smtp_password` VARCHAR(255) NOT NULL,
  `from_email` VARCHAR(191) NOT NULL,
  `from_name` VARCHAR(191) DEFAULT 'IT Support',
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Reusable email templates (send_email.php)
CREATE TABLE IF NOT EXISTS `email_templates` (
  `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `template_name` VARCHAR(191) NOT NULL,
  `subject` VARCHAR(255) NOT NULL,
  `message` TEXT NOT NULL,
  `link_text` VARCHAR(100) DEFAULT 'Verify Account →',
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Sample seed data
INSERT IGNORE INTO employees (name, email, department) VALUES
  ('Alice Admin','alice@example.test','Management'),
  ('Bob Buyer','bob@example.test','Sales'),
  ('Carol HR','carol@example.test','HR');

INSERT IGNORE INTO campaigns (campaign_name, template_type, sent_at) VALUES
  ('Quarterly Awareness', 'IT_Support', NOW());