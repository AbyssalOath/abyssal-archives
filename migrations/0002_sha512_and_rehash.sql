-- SHA-512 alongside SHA-256. Nullable: rows created before this migration
-- have no SHA-512 until "Recompute hashes" backfills it (the UI shows "n/a").
-- 'hashing' marks a file whose hashes are being recomputed in the background.
ALTER TABLE files
    ADD COLUMN sha512 CHAR(128) NULL AFTER sha256,
    MODIFY COLUMN status ENUM('importing', 'hashing', 'ready', 'failed') NOT NULL DEFAULT 'ready';
