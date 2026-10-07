-- Initial schema. IDs and counters are signed BIGINT so they map cleanly to
-- Rust i64. All text is utf8mb4.

-- Key/value site settings (site_name, site_tagline, footer_text, ...).
CREATE TABLE site_settings (
    `key`   VARCHAR(64) NOT NULL PRIMARY KEY,
    `value` TEXT        NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Accounts. Only one admin exists in the MVP; 'member' is reserved for
-- future multi-user hosting (see docs/FUTURE.md).
CREATE TABLE users (
    id            BIGINT       NOT NULL AUTO_INCREMENT PRIMARY KEY,
    username      VARCHAR(64)  NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role          VARCHAR(16)  NOT NULL DEFAULT 'member',
    created_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_users_username (username),
    CONSTRAINT chk_users_role CHECK (role IN ('admin', 'member'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Server-side sessions. `id` is the SHA-256 (hex) of the cookie token, so a
-- database leak does not hand out live sessions.
CREATE TABLE sessions (
    id         CHAR(64) NOT NULL PRIMARY KEY,
    user_id    BIGINT   NOT NULL,
    csrf_token CHAR(64) NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,
    KEY idx_sessions_user (user_id),
    KEY idx_sessions_expires (expires_at),
    CONSTRAINT fk_sessions_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE projects (
    id             BIGINT       NOT NULL AUTO_INCREMENT PRIMARY KEY,
    slug           VARCHAR(64)  NOT NULL,
    name           VARCHAR(200) NOT NULL,
    summary        VARCHAR(500) NOT NULL DEFAULT '',
    description_md MEDIUMTEXT   NOT NULL,
    owner_id       BIGINT       NULL,
    created_at     DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_projects_slug (slug),
    KEY idx_projects_owner (owner_id),
    KEY idx_projects_name (name),
    CONSTRAINT fk_projects_owner FOREIGN KEY (owner_id) REFERENCES users (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE releases (
    id          BIGINT      NOT NULL AUTO_INCREMENT PRIMARY KEY,
    project_id  BIGINT      NOT NULL,
    version     VARCHAR(64) NOT NULL,
    notes_md    MEDIUMTEXT  NOT NULL,
    released_at DATE        NOT NULL,
    created_at  DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_releases_project_version (project_id, version),
    KEY idx_releases_project_date (project_id, released_at),
    CONSTRAINT fk_releases_project FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Files. The bytes live in a storage backend under `storage_key` (an opaque
-- UUID); `filename` is the sanitized original name, used only for display and
-- Content-Disposition. `storage_backend` allows mixing backends later.
-- `status` tracks background imports from INCOMING_PATH: only 'ready' files
-- are ever listed publicly or downloadable.
CREATE TABLE files (
    id               BIGINT        NOT NULL AUTO_INCREMENT PRIMARY KEY,
    release_id       BIGINT        NOT NULL,
    filename         VARCHAR(255)  NOT NULL,
    size_bytes       BIGINT        NOT NULL DEFAULT 0,
    sha256           CHAR(64)      NOT NULL DEFAULT '',
    storage_backend  VARCHAR(16)   NOT NULL,
    storage_key      VARCHAR(255)  NOT NULL,
    download_count   BIGINT        NOT NULL DEFAULT 0,
    status           ENUM('importing', 'ready', 'failed') NOT NULL DEFAULT 'ready',
    error_message    VARCHAR(512)  NULL,
    mirror_url       VARCHAR(2048) NULL,
    torrent_infohash CHAR(40)      NULL,
    created_at       DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_files_storage (storage_backend, storage_key),
    KEY idx_files_release_status (release_id, status),
    CONSTRAINT fk_files_release FOREIGN KEY (release_id) REFERENCES releases (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
