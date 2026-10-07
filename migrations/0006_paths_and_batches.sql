-- Folder paths inside releases, the recommended file, bulk imports and the
-- audit log. Additive: existing files keep their name as their path, so no
-- URL changes.

-- `path` is the file's place in the release tree, e.g. "sources/a.tar.gz"
-- (`filename` stays the last component). Older versions allowed the same
-- name twice in a release; such later copies get "~<id>" appended to their
-- path so the new unique key can be added (their files are untouched).
ALTER TABLE files ADD COLUMN path VARCHAR(512) NULL AFTER filename;
UPDATE files SET path = filename;
UPDATE files f
  JOIN (SELECT id, ROW_NUMBER() OVER (PARTITION BY release_id, filename ORDER BY id) AS n
        FROM files) d ON d.id = f.id
   SET f.path = CONCAT(f.filename, '~', f.id)
 WHERE d.n > 1;
ALTER TABLE files
    MODIFY path VARCHAR(512) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    ADD UNIQUE KEY uq_files_release_path (release_id, path);

-- The file /p/<project>/latest/download points at.
ALTER TABLE releases
    ADD COLUMN recommended_file_id BIGINT NULL,
    ADD CONSTRAINT fk_releases_recommended FOREIGN KEY (recommended_file_id)
        REFERENCES files (id) ON DELETE SET NULL;

-- A bulk import (web "Import all", single imports and the CLI) and its
-- per-file results. Items are processed one at a time.
CREATE TABLE import_batches (
    id          BIGINT       NOT NULL AUTO_INCREMENT PRIMARY KEY,
    release_id  BIGINT       NOT NULL,
    user_id     BIGINT       NULL,
    -- "web" or "cli".
    source      VARCHAR(8)   NOT NULL,
    -- The incoming subfolder imported ("" = the whole folder, or one file).
    folder      VARCHAR(512) NOT NULL DEFAULT '',
    created_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    finished_at DATETIME     NULL,
    KEY idx_import_batches_release (release_id, id),
    CONSTRAINT fk_import_batches_release FOREIGN KEY (release_id) REFERENCES releases (id) ON DELETE CASCADE,
    CONSTRAINT fk_import_batches_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE import_items (
    id          BIGINT       NOT NULL AUTO_INCREMENT PRIMARY KEY,
    batch_id    BIGINT       NOT NULL,
    path        VARCHAR(512) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    size_bytes  BIGINT       NOT NULL DEFAULT 0,
    -- queued, importing, done, skipped, failed
    status      VARCHAR(16)  NOT NULL DEFAULT 'queued',
    message     VARCHAR(512) NULL,
    file_id     BIGINT       NULL,
    finished_at DATETIME     NULL,
    KEY idx_import_items_batch (batch_id, status),
    CONSTRAINT fk_import_items_batch FOREIGN KEY (batch_id) REFERENCES import_batches (id) ON DELETE CASCADE,
    CONSTRAINT fk_import_items_file FOREIGN KEY (file_id) REFERENCES files (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Deletions, publishing changes and other consequential actions. The
-- username is copied so entries outlive deleted accounts.
CREATE TABLE audit_log (
    id         BIGINT        NOT NULL AUTO_INCREMENT PRIMARY KEY,
    created_at DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    user_id    BIGINT        NULL,
    username   VARCHAR(64)   NOT NULL,
    action     VARCHAR(32)   NOT NULL,
    target     VARCHAR(700)  NOT NULL,
    detail     VARCHAR(1000) NULL,
    KEY idx_audit_log_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
