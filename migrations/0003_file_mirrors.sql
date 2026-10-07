-- Admin-curated mirrors, replacing the single files.mirror_url column.
-- Additive first: create the table and copy every existing mirror_url into
-- an approved, admin-sourced http mirror; only then drop the old column.
CREATE TABLE file_mirrors (
    id              BIGINT        NOT NULL AUTO_INCREMENT PRIMARY KEY,
    file_id         BIGINT        NOT NULL,
    url             VARCHAR(2048) NOT NULL,
    label           VARCHAR(100)  NOT NULL DEFAULT '',
    kind            ENUM('http', 'torrent') NOT NULL DEFAULT 'http',
    status          ENUM('pending', 'approved', 'rejected', 'failed') NOT NULL DEFAULT 'pending',
    source          ENUM('admin', 'discovered', 'federated') NOT NULL DEFAULT 'admin',
    last_checked_at DATETIME      NULL,
    last_error      VARCHAR(512)  NULL,
    created_at      DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    KEY idx_file_mirrors_file_status (file_id, status),
    CONSTRAINT fk_file_mirrors_file FOREIGN KEY (file_id) REFERENCES files (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Label: the URL's host name (e.g. "archive.org").
INSERT INTO file_mirrors (file_id, url, label, kind, status, source)
SELECT id,
       mirror_url,
       LEFT(SUBSTRING_INDEX(SUBSTRING_INDEX(SUBSTRING_INDEX(mirror_url, '://', -1), '/', 1), ':', 1), 100),
       'http',
       'approved',
       'admin'
FROM files
WHERE mirror_url IS NOT NULL AND mirror_url <> '';

ALTER TABLE files DROP COLUMN mirror_url;
