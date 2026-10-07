-- Copies of published files in Cloudflare R2 (src/r2.rs, docs/DOWNLOADS.md).
-- No foreign key on file_id: a row outlives its deleted file until the sync
-- job has removed the object from the bucket.
CREATE TABLE r2_objects (
    file_id    BIGINT        NOT NULL PRIMARY KEY,
    object_key VARCHAR(700)  CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    size_bytes BIGINT        NOT NULL,
    -- "uploaded" or "failed"
    status     VARCHAR(16)   NOT NULL,
    error      VARCHAR(512)  NULL,
    updated_at DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    KEY idx_r2_objects_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
