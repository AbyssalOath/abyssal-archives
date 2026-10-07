# Security and privacy review

Reviewed as an attacker against commit `d2fa545`, then fixed with the
smallest sensible changes. Severity is for a single-admin public download
site behind a reverse proxy / Cloudflare Tunnel.

Status: **FIXED**, **ALREADY OK** (verified, no change), **DEFERRED** (with
reason); later features are recorded as **NEW** (security-relevant design,
tested) or **NOTE**. Every fix has tests (unit tests, `tests/security.rs`,
`tests/integration.rs`) unless noted as verified manually.

| # | Area | File(s) | Severity | Status | Note |
|---|---|---|---|---|---|
| 1 | Auth | `src/util.rs` | Low | FIXED | Tokens, CSRF, TOTP secrets, nonces and recovery codes come straight from the OS CSPRNG (`getrandom`) |
| 2 | Auth | `src/routes/auth.rs` | - | ALREADY OK | Only SHA-256(token) is stored; migration 0004 additionally invalidates all pre-upgrade sessions |
| 3 | Auth | `src/routes/auth.rs`, `src/db/queries.rs` | Medium | FIXED | Idle (30 min) and absolute (12 h) timeouts, configurable, enforced in SQL |
| 4 | Auth | `src/state.rs` | Low | FIXED | Background purge of expired/idle sessions every 10 min |
| 5 | Auth | `src/routes/auth.rs` | Low | FIXED | Every login (and 2FA step) rotates: the browser's previous session is deleted; planted cookies are never adopted |
| 6 | Auth | `src/routes/auth.rs` | Low | FIXED | `__Host-sid` / `__Host-csrf_pre`, Secure from COOKIE_SECURE only, HttpOnly, SameSite=Strict |
| 7 | Auth | `src/routes/auth.rs`, `src/config.rs` | Low | FIXED | Argon2id m=19456 KiB, t=2, p=1 (OWASP), configurable; outdated hashes upgraded at login |
| 8 | Auth | `src/routes/auth.rs` | - | ALREADY OK | Same message and dummy-hash timing for unknown users and wrong passwords |
| 9 | Auth | `src/ratelimit.rs` | Medium | FIXED | Per IP **and** per username; after 5 failures exponential lockout 30 s → 15 min |
| 10 | Privacy | `src/net.rs`, `src/routes/*` | Medium | FIXED | LOG_IP_MODE (default truncated /24, /48) in access, auth and limit logs; no usernames, passwords, cookies, tokens or query strings logged |
| 11 | CSRF | `src/guard.rs` | Low | FIXED | Every POST also needs a same-origin Origin (or Referer): PUBLIC_URL, ADMIN_HOST, or the request's own Host; missing/`null` refused |
| 12 | Auth | `src/routes/account.rs` | Medium | FIXED | /admin/password: current password required, other sessions ended, rate-limited |
| 13 | Auth | `src/totp.rs`, `src/routes/account.rs` | Medium | FIXED | Opt-in TOTP (TOTP_ENABLED): AES-256-GCM-encrypted secret, single-use codes (replay-proof), 10 hashed recovery codes, server-rendered SVG QR, CLI `admin reset-2fa` |
| 14 | Proxy | `src/net.rs` | Medium | FIXED | TRUSTED_PROXIES (default loopback + 172.16/12); X-Forwarded-For walked past trusted hops; optional CF-Connecting-IP; LAN clients no longer trusted |
| 15 | Admin | `src/guard.rs`, `src/routes/auth.rs` | Medium | FIXED | Opt-in ADMIN_ALLOWED_CIDRS and ADMIN_HOST (404 otherwise); docs for Cloudflare Access. Since member accounts (#56) they guard /admin, /setup, the admin's sign-in (same answer as a wrong password) and the admin's session, not /login itself |
| 16 | Admin | `src/guard.rs` | Low | FIXED | `Cache-Control: no-store` on all admin/auth responses |
| 17 | Admin | `src/routes/auth.rs` | - | ALREADY OK | `/setup` impossible once any user exists (now tested, GET and POST) |
| 18 | Admin | `src/routes/auth.rs`, `install.sh` | Low | FIXED | SETUP_ENABLED; install.sh sets it false once an admin exists |
| 19 | Headers | `src/routes/mod.rs` | Medium | FIXED | CSP `img-src 'self'`, `font-src 'none'`, `connect-src 'none'` (no third-party loads possible) |
| 20 | Headers | `src/routes/mod.rs`, `src/guard.rs` | Low | FIXED | Referrer-Policy no-referrer (public) / same-origin (admin and auth pages, see #55), COOP/CORP same-origin, deny-all Permissions-Policy, opt-in HSTS (HTTPS via trusted proxy only) |
| 21 | Headers | `install.sh`, `Caddyfile.example` | Low | FIXED | Generated Caddyfiles strip `Server`; existing ones get a hint (never rewritten) |
| 22 | Downloads | `src/util.rs` | Low | FIXED | RFC 6266 attachment + RFC 5987 `filename*`, injection-proof for any name; nosniff on downloads |
| 23 | Markdown | `src/markdown.rs` | Medium | FIXED | Raw HTML shown as text; explicit ammonia allowlist; http/https/mailto only; nofollow; remote images dropped |
| 24 | Limits | `src/routes/mod.rs` | Low | FIXED | 64 KiB body limit outside the upload route; text fields capped at 60 000 bytes |
| 25 | Limits | `src/lib.rs`, `src/limits.rs` | Medium | FIXED | Own accept loop: 10 s header read timeout, 64 KiB head, 100 headers, MAX_CONNECTIONS / _PER_IP (verified with live slowloris tests) |
| 26 | Limits | `src/guard.rs` | Low | FIXED | REQUEST_TIMEOUT_SECS (30) for everything but downloads/uploads |
| 27 | Limits | `src/routes/public.rs` | Medium | FIXED | DOWNLOAD_MAX_CONCURRENT / _PER_IP; the slot is held until the body is sent |
| 28 | Limits | `src/guard.rs` | Low | FIXED | RATE_LIMIT_PER_MINUTE per client IP (generous), 429 + Retry-After |
| 29 | Limits | `src/range.rs` | Low | FIXED | Multi-range and oversized Range headers refused (416) |
| 30 | Imports | `src/routes/admin.rs`, `src/limits.rs` | Medium | FIXED | IMPORT_CONCURRENCY job queue (imports, recomputes, integrity checks); STORAGE_MIN_FREE_BYTES reserve |
| 31 | Files | `src/fsid.rs`, `src/storage/local.rs` | Medium | FIXED | O_NOFOLLOW/O_NONBLOCK open, fstat on the descriptor (regular, nlink 1), (dev, inode, size, mtime) pinned from request to hash to move; copy fallback reads the verified descriptor |
| 32 | Files | `src/storage/local.rs` | - | ALREADY OK | Keys must be canonical UUIDs before any filesystem call |
| 33 | Files | `src/storage/local.rs`, `src/lib.rs` | Low | FIXED | Directories 0700, objects 0600, process umask 077 (via rustix, no unsafe) |
| 34 | Files | `src/integrity.rs` | Low | FIXED | Background "Verify storage integrity" on the dashboard |
| 35 | SSRF | `src/mirrors.rs` | - | ALREADY OK | Guarded resolver: connect only to validated addresses (pinned per connection, Host/SNI unchanged), re-validated per hop; rebinding now tested |
| 36 | SSRF | `src/mirrors.rs` | Low | FIXED | Explicit tests for 169.254.169.254, fd00:ec2::/16, 100.100.100.200, IPv4-mapped/NAT64/6to4 |
| 37 | Privacy | `src/mirrors.rs` | Low | FIXED | VERIFY_PROXY_URL (http/https/socks5/socks5h) with local pre-check; User-Agent without version |
| 38 | Privacy | `templates/base.html` | Low | FIXED | Footer "Admin" link hidden when ADMIN_HOST is set; now a "Login" link to the current host's /login, which never reveals the admin host |
| 39 | Privacy | `src/routes/public.rs` | - | ALREADY OK | No cookies, no per-visitor rows, aggregate counter only (docs/PRIVACY.md) |
| 40 | Docker | `docker-compose.yml`, `Dockerfile` | Medium | FIXED | Distroless runtime (no shell), UID 10001, read-only root fs + tmpfs /tmp, cap_drop ALL, no-new-privileges, pids/mem/cpu limits |
| 41 | Docker | `Dockerfile`, `docker-compose.yml` | Medium | FIXED | Every image pinned by digest; Dependabot for docker, compose, actions, cargo |
| 42 | Docker | `docker-compose.yml` | Low | FIXED | MariaDB on an internal network with the app only; no host port unless DB_PUBLISH=true |
| 43 | Docker | `docker-compose.yml` | - | ALREADY OK | App uses MARIADB_USER (own database only); root password only in the DB container |
| 44 | Docker | `docker-compose.yml` | Low | FIXED | qBittorrent: cap_drop ALL + only what its init needs, no-new-privileges; only gluetun has NET_ADMIN; Caddy only NET_BIND_SERVICE |
| 45 | Install | `install.sh` | Low | FIXED | `.env` forced to 600 with a warning; warning for world-writable data dirs |
| 46 | Seeder | `install.sh` | Medium | FIXED | Option 3 now fails closed like enable-seeder.sh (stop, remove, drop profile) |
| 47 | Supply chain | `src/lib.rs`, `src/main.rs` | Low | FIXED | `#![forbid(unsafe_code)]`; umask/statvfs/O_NOFOLLOW via rustix's safe API |
| 48 | Supply chain | `.github/` | Medium | FIXED | cargo-deny (advisories, licenses, bans, sources) + cargo-audit, gitleaks over full history, Trivy (HIGH/CRITICAL, fixable), CycloneDX SBOM artifact, per-job read-only permissions, SHA-pinned actions, Dependabot |
| 49 | Supply chain | `SECURITY.md` | Low | FIXED | Private disclosure via GitHub Security Advisories |
| 50 | Authenticity | `src/routes/public.rs`, `src/routes/admin.rs` | Low | FIXED | Admin-made detached signature served as SHA256SUMS.asc only while it matches the current SUMS; /gpg.pub; no private key on the server |
| 51 | Backups | `scripts/backup.sh` | Low | FIXED | Owner-only dump + config archive, optional age/gpg, never inside storage/incoming/data; docs/BACKUP.md |
| 52 | Limits | `src/lib.rs` | Medium | FIXED | Found while testing: hyper-util's HTTP/1-vs-2 sniff read had no timeout, so silent connections stayed open forever; now dropped after 10 s |
| 53 | Proxy | Docker | Low | DEFERRED | Connections through Docker's userland proxy (host-originated or IPv6) arrive from the bridge gateway, which is in the default trusted range. Can't be fixed in the app; documented (keep the app port behind the proxy / on localhost, or narrow TRUSTED_PROXIES) |
| 55 | CSRF | `src/guard.rs` | High | FIXED | Regression from #11 + #20, found in a real browser after release: under `Referrer-Policy: no-referrer` browsers submit forms with `Origin: null` and no Referer, so every form (setup, login, admin) was refused with 403. Admin/auth pages now send `same-origin`; reproduced and verified with headless Chromium; tests assert the per-page policy |
| 54 | Install | `install.sh`, `scripts/lib/seeder-setup.sh` | - | FIXED | Root helper containers moved from the app image (now shell-less) to the MariaDB image |
| 56 | Members | `src/routes/auth.rs`, `src/routes/admin.rs` | - | NEW | Member accounts (docs/MEMBERS.md): role checks in one extractor (`Actor`: /admin admins only, /my members only); every project/release/file handler loads through an ownership check (404 for others' items); admin-only handlers take `AdminUser`. Tested: cross-member access, admin-only actions, member on /admin |
| 57 | Members | `src/db/queries.rs`, `src/routes/public.rs` | - | NEW | Review before publishing: every public query (home, project page, downloads, torrent, per-file checksums, SUMS, .asc, mirrors) requires an approved release of an approved project; unpublished files only via the owner's / admin's workspace link |
| 58 | Members | `src/routes/auth.rs`, `src/ratelimit.rs` | Low | NEW | /register: off by default, pre-login CSRF, per-IP backoff counted before the Argon2 hash, cap of 100 pending requests; pending/disabled state shown only after the right password; sessions of non-active accounts never valid |
| 59 | Members | `src/routes/admin.rs` | Low | NEW | Member upload limit and quota enforced on the byte stream (oversized uploads are dropped, never stored); member limit never above MAX_UPLOAD_BYTES. Concurrent uploads can overshoot the quota by at most one file (accepted) |
| 60 | Members | `src/routes/auth.rs` | - | NOTE | Usernames are unique (case-insensitive), so /register reveals whether a name is taken; inherent to choosing a name, and rate-limited |
| 61 | Files | `src/util.rs`, `src/importer.rs`, `migrations/0006_paths_and_batches.sql` | - | NEW | Folder paths in releases: every component sanitized, at most 3 folder levels and 512 bytes, incoming paths still resolved and pinned as before (no `..`, symlinks or hard links); generated root names (SHA256SUMS, SHA512SUMS, .asc, files.json) refused; `(release_id, path)` unique in the database, so a path is never overwritten, even by concurrent imports |
| 62 | Files | `src/routes/public.rs` | - | NEW | /p/<project>/<version>/<path> serves only ready files of published releases of published projects (same rules as /download/<id>), looked up by exact path in the database, never through the file system |
| 63 | Imports | `src/importer.rs`, `src/main.rs` | - | NEW | Bulk import: whole batch refused before copying when it would cut into STORAGE_MIN_FREE_BYTES, each file re-checked before its copy; skip only after a full SHA-256 match; one file at a time (verified: 3 GiB import with 11 MB peak memory); the `import` command runs without restart recovery so it cannot fail the server's running imports |
| 65 | R2 | `src/r2.rs`, `src/routes/storage.rs` | - | NEW | Optional R2 download origin: off by default; the secret key AES-256-GCM sealed with a key derived (HMAC-SHA256) from TOTP_ENCRYPTION_KEY, write-only in the UI, redacted in Debug, never logged; fixed endpoint `<account>.r2.cloudflarestorage.com` (32-hex account ID, no SSRF); the connection test fetches through the guarded mirror-Verify client; only published files are uploaded, unpublished/deleted ones are removed; redirects only to copies recorded as uploaded, with `Cache-Control: no-store`; uploads signed with the recorded SHA-256 (per part for multipart). SigV4 tested against the AWS example; uploads, multipart, wrong-hash rejection, head and delete tested against MinIO |
| 64 | Deletion | `src/routes/admin.rs`, `src/routes/members.rs` | - | NEW | Deleting a published project, release or file needs its slug, version or path typed; accounts need the username typed; deletions and publish/unpublish are written to an audit log (/admin/log, admin only) |

## Not changed, by design

- Single-instance, in-memory rate limiting and connection tracking (reset on
  restart): adequate for one container; a shared store would be needed to
  scale out.
- The per-username login backoff lets anyone delay the admin's login by at
  most 15 minutes at a time; that bound is deliberate (an IP allowlist or
  ADMIN_HOST + Cloudflare Access removes the exposure entirely).
- The `.asc` signature is validated as ASCII armor but not cryptographically
  verified by the server (that would need the private key's counterpart and
  an OpenPGP implementation); it is only served while it was made for the
  current SHA256SUMS content, and downloaders verify it themselves.

## Secret scanning

`gitleaks git` (v8.30.1, pinned image) over the full history at the time of
this review: 8 commits scanned, **no leaks found**. The only key-like
strings in the repository are test fixtures (e.g. the all-sequential-bytes
TOTP test key) and public example values in `.env.example`.
