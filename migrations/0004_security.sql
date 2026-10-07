-- Security hardening (docs/SECURITY-REVIEW.md). Additive only.

-- Sessions: idle timeout (last_seen_at) and a pending-second-factor state.
-- Existing sessions are invalidated: the cookie name changes (__Host- prefix)
-- and they were created under the old 7-day lifetime. Users just log in again.
DELETE FROM sessions;
ALTER TABLE sessions
    ADD COLUMN last_seen_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP AFTER created_at,
    ADD COLUMN mfa_pending  TINYINT  NOT NULL DEFAULT 0 AFTER last_seen_at;

-- Optional TOTP second factor. The secret is AES-256-GCM encrypted with
-- TOTP_ENCRYPTION_KEY (nonce || ciphertext); never stored in clear.
ALTER TABLE users
    ADD COLUMN totp_secret_enc VARBINARY(128) NULL,
    ADD COLUMN totp_enabled    TINYINT        NOT NULL DEFAULT 0,
    -- Last accepted TOTP time step: every code works only once.
    ADD COLUMN totp_last_step  BIGINT         NULL;

-- Single-use recovery codes, stored as SHA-256 of the code (80-bit random).
CREATE TABLE user_recovery_codes (
    id        BIGINT   NOT NULL AUTO_INCREMENT PRIMARY KEY,
    user_id   BIGINT   NOT NULL,
    code_hash CHAR(64) NOT NULL,
    used_at   DATETIME NULL,
    UNIQUE KEY uq_recovery_user_code (user_id, code_hash),
    CONSTRAINT fk_recovery_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Detached signature of a release's SHA256SUMS, made by the admin on their
-- own machine and pasted in /admin (the server never holds a private key).
-- sums_signed_sha256 is the SHA-256 of the SHA256SUMS content it was made
-- for; once the file set changes the signature is no longer served.
ALTER TABLE releases
    ADD COLUMN sums_signature      TEXT     NULL,
    ADD COLUMN sums_signed_sha256  CHAR(64) NULL,
    ADD COLUMN sums_signed_at      DATETIME NULL;
