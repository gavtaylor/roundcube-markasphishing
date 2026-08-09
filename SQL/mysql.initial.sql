-- markasphishing: report recipient directory
--
-- A single table holds both provider abuse desks (matched by the sending
-- domain) and global reporting authorities (always included, domain NULL).
-- They're the same shape of data -- name/address/enabled -- so one table
-- with a `type` discriminator avoids duplicating schema and CRUD code for
-- what would otherwise be two near-identical tables.
--
-- One row per provider, not per domain: `domain` holds a comma-separated
-- list (e.g. 'gmail.com, googlemail.com') when a provider owns more than
-- one. Matching happens in PHP (markasphishing::_lookup_recipients()),
-- not via a SQL WHERE domain = ?, so no index on it.

CREATE TABLE IF NOT EXISTS `markasphishing_recipients` (
    `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
    `type` ENUM('provider', 'authority') NOT NULL,
    `domain` VARCHAR(255) DEFAULT NULL,
    `name` VARCHAR(255) NOT NULL,
    `report_address` VARCHAR(255) NOT NULL,
    `enabled` TINYINT(1) NOT NULL DEFAULT 1,
    `is_default` TINYINT(1) NOT NULL DEFAULT 0,
    `description` VARCHAR(255) DEFAULT NULL,
    PRIMARY KEY (`id`),
    KEY `markasphishing_recipients_type_idx` (`type`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Seed data, gathered from public provider/authority support documentation
-- (Aug 2026). Best-effort: verify before relying on this in a real incident,
-- and expect some addresses to go stale over time -- manage via the plugin's
-- settings page rather than editing this file after install.

INSERT INTO `markasphishing_recipients` (`type`, `domain`, `name`, `report_address`, `enabled`, `is_default`, `description`) VALUES
('provider', 'gmail.com, googlemail.com', 'Gmail', 'abuse@gmail.com', 1, 1, NULL),
('provider', 'outlook.com, hotmail.com, live.com, msn.com', 'Microsoft (Outlook/Hotmail/Live)', 'phish@office365.microsoft.com', 1, 1, NULL),
('provider', 'yahoo.com, yahoo.co.uk, ymail.com, rocketmail.com', 'Yahoo', 'abuse@yahoo.com', 1, 1, NULL),
('provider', 'icloud.com, me.com, mac.com', 'iCloud', 'abuse@icloud.com', 1, 1, NULL),
('authority', NULL, 'NCSC Suspicious Email Reporting Service (UK)', 'report@phishing.gov.uk', 1, 1, 'National Cyber Security Centre, part of GCHQ'),
('authority', NULL, 'Anti-Phishing Working Group (APWG)', 'reportphishing@apwg.org', 1, 1, 'Global cross-industry anti-phishing coalition');

-- Tracks which messages have already been reported (by Message-ID, globally
-- across all users on the instance) so a duplicate report -- the same
-- message reopened, or the same phishing blast landing in several mailboxes
-- -- doesn't send the same report again. Rows older than
-- markasphishing_dedupe_retention_days are opportunistically cleaned up
-- from PHP (see markasphishing::_gc_reported()) rather than via a cronjob,
-- since Roundcube core gives plugins no hook into its own gc.sh.

CREATE TABLE IF NOT EXISTS `markasphishing_reported` (
    `message_id` VARCHAR(255) NOT NULL,
    `reported_at` DATETIME NOT NULL,
    PRIMARY KEY (`message_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Per-recipient send log: one row per report email actually attempted
-- (successful or not), so stats can show which providers/authorities get
-- reported to, how often deliveries fail, and which mailbox on this
-- instance is receiving the phishing (a mailbox showing up disproportionately
-- often is worth a closer look/security awareness follow-up) -- detail
-- markasphishing_reported deliberately doesn't carry, since it exists only
-- for dedupe. Cleaned up on the same opportunistic schedule and retention
-- window as markasphishing_reported (see markasphishing::_gc_reported()).

CREATE TABLE IF NOT EXISTS `markasphishing_report_log` (
    `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
    `message_id` VARCHAR(255) NOT NULL,
    `recipient` VARCHAR(255) NOT NULL,
    `username` VARCHAR(255) NOT NULL,
    `success` TINYINT(1) NOT NULL,
    `sent_at` DATETIME NOT NULL,
    PRIMARY KEY (`id`),
    KEY `markasphishing_report_log_recipient_idx` (`recipient`),
    KEY `markasphishing_report_log_username_idx` (`username`),
    KEY `markasphishing_report_log_sent_at_idx` (`sent_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
