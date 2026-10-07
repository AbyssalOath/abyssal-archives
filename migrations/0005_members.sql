-- Member accounts (docs/MEMBERS.md). Additive only: existing users stay
-- active, existing projects and releases stay published.

-- Accounts requested through /register start 'pending' until an admin
-- approves them; 'disabled' accounts cannot sign in. NULL limits mean the
-- site-wide member defaults (set in /admin/settings).
ALTER TABLE users
    ADD COLUMN status              VARCHAR(16)   NOT NULL DEFAULT 'active',
    ADD COLUMN signup_note         VARCHAR(1000) NULL,
    ADD COLUMN upload_limit_bytes  BIGINT        NULL,
    ADD COLUMN storage_quota_bytes BIGINT        NULL,
    ADD CONSTRAINT chk_users_status CHECK (status IN ('active', 'pending', 'disabled'));

-- Review of member content: only 'approved' projects and releases are
-- public. Admin-made content is always 'approved'.
ALTER TABLE projects
    ADD COLUMN review_status VARCHAR(16)  NOT NULL DEFAULT 'approved',
    ADD COLUMN review_note   VARCHAR(500) NULL,
    ADD KEY idx_projects_review (review_status),
    ADD CONSTRAINT chk_projects_review CHECK (review_status IN ('approved', 'pending', 'rejected'));

ALTER TABLE releases
    ADD COLUMN review_status VARCHAR(16)  NOT NULL DEFAULT 'approved',
    ADD COLUMN review_note   VARCHAR(500) NULL,
    ADD KEY idx_releases_review (review_status),
    ADD CONSTRAINT chk_releases_review CHECK (review_status IN ('approved', 'pending', 'rejected'));

-- A member's request for a higher upload limit and/or storage quota.
CREATE TABLE limit_requests (
    id                  BIGINT        NOT NULL AUTO_INCREMENT PRIMARY KEY,
    user_id             BIGINT        NOT NULL,
    upload_limit_bytes  BIGINT        NULL,
    storage_quota_bytes BIGINT        NULL,
    reason              VARCHAR(1000) NOT NULL,
    status              VARCHAR(16)   NOT NULL DEFAULT 'pending',
    admin_note          VARCHAR(500)  NULL,
    created_at          DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    decided_at          DATETIME      NULL,
    KEY idx_limit_requests_user (user_id),
    KEY idx_limit_requests_status (status),
    CONSTRAINT fk_limit_requests_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    CONSTRAINT chk_limit_requests_status CHECK (status IN ('pending', 'approved', 'denied'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
