# Abyssal Archives

[![CI](https://github.com/AbyssalOath/abyssal-archives/actions/workflows/ci.yml/badge.svg)](https://github.com/AbyssalOath/abyssal-archives/actions/workflows/ci.yml)
[![License: AGPL v3+](https://img.shields.io/badge/license-AGPL--3.0--or--later-red.svg)](LICENSE)

A small, self-hosted, SourceForge-style file hosting site: projects, releases
and downloadable files with sizes, SHA-256 checksums and download counts.
Written in Rust (axum, Askama, MariaDB via sqlx), fully server-rendered, with
**zero JavaScript**. Ships as a Docker Compose stack.

The site's name is not built in: you choose it at install time and can change
it any time from the admin settings page. (The code itself is called
`filehost`; nothing in it carries a brand.)

- Public: project list, project and release pages (Markdown descriptions and
  release notes), releases with folders (`sources/a.tar.gz`, collapsed on the
  page, main downloads first), a recommended file per release, and **stable
  direct download URLs** (`/p/<project>/<version>/<path>`, plain GET with
  Range / resume, works with curl and wget), plus `/p/<project>/latest` and
  `/p/<project>/latest/download` ([docs/DOWNLOADS.md](docs/DOWNLOADS.md)).
- Optional **Cloudflare R2** download origin (Admin, Storage): published files
  are copied to your bucket and the same URLs redirect there, while this
  server keeps the master copy ([docs/DOWNLOADS.md](docs/DOWNLOADS.md)).
- Integrity: SHA-256 and SHA-512 for every file (computed in one streaming pass),
  `SHA256SUMS` / `SHA512SUMS` per release (by path, for `sha256sum -c`), and a
  machine-readable `files.json` per release.
- Hardened by default (see [Security](#security)): no cookies or trackers for
  visitors, strict CSP, session/CSRF/Origin protection, rate limits, optional
  TOTP 2FA, distroless read-only container.
- External sharing, **all off by default**: admin-curated mirrors and torrent
  links (Archive.org, GitHub, other servers), and an optional, advanced
  self-seeding setup that runs qBittorrent only inside a VPN container.
- Admin: projects, releases, files, site settings, users and a review queue.
- Members (optional, see [docs/MEMBERS.md](docs/MEMBERS.md)): accounts created
  by the admin or requested at /register and approved; each member manages only
  their own projects, within an upload limit and storage quota, and (by
  default) nothing they publish is public until the admin reviews it.
- Large files (multi-GB ISOs, hundreds of source tarballs) are copied to the
  server out of band (rsync, scp, SMB) into an **incoming folder** and
  **imported** in the background: one file, a folder, or everything at once
  (also from the command line), with per-file results; reruns skip what is
  already there and existing files are never overwritten. Small files can also
  be uploaded from the browser.
- No casual deletion: published releases and files are deleted only by typing
  their name, unpublishing hides a release but keeps its files, and deletions
  and publishing changes are logged.
- Black-and-red theme with a slow pulsating glow (CSS only, disabled for
  `prefers-reduced-motion`).

## Quick start

```bash
git clone https://github.com/AbyssalOath/abyssal-archives.git
cd abyssal-archives
./install.sh
```

Then open the URL it prints, go to **`/setup`** and create the administrator
account. There is no default password: the account doesn't exist until you
create it, and `/setup` can never create an account again afterwards (it
then points visitors at `/register`, see [docs/MEMBERS.md](docs/MEMBERS.md)).

Requirements: Docker Engine with the Compose plugin, `openssl`, `bash`.

## What install.sh does

`install.sh` is idempotent: every question is skipped when its answer is
already in `.env`, secrets are never regenerated, and existing values are
never changed. Settings added by newer versions are appended with their
defaults, so re-running it is also how you upgrade (see [Upgrading](#upgrading)).

1. Checks for `docker`, `docker compose` and `openssl`.
2. Creates `.env` (mode 600) with random database passwords
   (`openssl rand -hex 24`). MariaDB gets no host port unless you set
   `DB_PUBLISH=true` (then only on `127.0.0.1:DB_PORT`).
3. Asks for the **site name** (required, no default), an optional **tagline**,
   and the **Docker project name** (default: the slugified site name), which
   prefixes all container, image and volume names. Values are quoted so spaces,
   `$`, `#` and quotes survive Docker Compose's `.env` parsing.
4. Creates the host folders for **storage** and **incoming** (`./data/storage`,
   `./data/incoming` by default) and gives the container user (UID/GID 10001)
   access: directly, with passwordless sudo, or through a one-off root
   container. If all of those fail it prints the exact `chown` command to run.
5. Asks for the host **HTTP port** (suggests the next free one if 8080 is taken).
6. Asks how HTTPS is handled:
   1. **Your own reverse proxy** (NGINX Proxy Manager, Cloudflare Tunnel,
      Traefik...): asks for the public HTTPS URL, sets `COOKIE_SECURE=true` and
      prints the upstream `http://<host-ip>:<port>` to point the proxy at.
   2. **Caddy** (bundled, `caddy` Compose profile): with a domain, writes a
      Caddyfile that gets a Let's Encrypt certificate automatically and binds
      the app port to `127.0.0.1`. Without a domain, uses Caddy's internal CA
      (`tls internal`) for a hostname or IP. Browsers will warn until Caddy's
      root CA is trusted (see [Caddy](#caddy)).
   3. **Local testing**: plain HTTP on `http://localhost:<port>`, `COOKIE_SECURE=false`.
7. Asks for an optional separate **download base URL** (e.g. `https://dl.example.com`).
8. Asks about **external sharing**:
   1. **None** (default).
   2. **Admin-curated mirrors/torrent links**: sets `EXTERNAL_MIRRORS_ENABLED=true`,
      no extra containers ([docs/MIRRORS.md](docs/MIRRORS.md)).
   3. **Self-seeding through a VPN container** (advanced, experimental; includes 2):
      prints the risks, requires typing `yes`, asks for the VPN provider and
      credentials (secrets typed hidden), generates `QBT_PASSWORD`, pre-seeds
      qBittorrent's config and enables the `seeder` profile
      ([docs/TORRENTS.md](docs/TORRENTS.md)).
9. Writes `COMPOSE_PROFILES` once, from all choices (e.g. `caddy,seeder`).
10. Runs `docker compose build` and `docker compose up -d`, then prints the URL,
   the enabled options, the `/setup` reminder, the incoming folder path with a
   ready-to-copy `rsync` command, and for option 3 the qBittorrent Web UI
   location (127.0.0.1 only, via SSH tunnel) and the result of
   `scripts/check-seeder-ip.sh`.

An existing `Caddyfile` is backed up (`Caddyfile.bak.<time>`) before
install.sh writes a new one, and an existing qBittorrent config is never
overwritten.

### Changing the site name or download URL later

- In the browser: **/admin/settings** (takes effect immediately).
- From the shell: `scripts/set-site-name.sh "New Name"` or
  `scripts/set-download-url.sh https://dl.example.com`, then
  `docker compose up -d app` (recreates the container with the new environment).

`SITE_NAME`, `SITE_TAGLINE` and `DOWNLOAD_BASE_URL` are copied from `.env`
into the database at every start **until** a different value is saved in
/admin/settings. From then on the admin page wins. To hand control back to
`.env`, save the same value as `.env` on the settings page, or run either script
with `--reset-override` (needs the stack running).

## Configuration

Everything is configured in `.env` (see [`.env.example`](.env.example), which
documents every variable). The app validates its settings at startup and
lists every problem at once.

| Variable | Default | Purpose |
|---|---|---|
| `COMPOSE_PROJECT_NAME` | `filehost` | Prefix for container, image and volume names |
| `COMPOSE_PROFILES` | *(empty)* | `caddy` to run the bundled Caddy |
| `HTTP_PORT` | `8080` | Host port for the app (container always listens on 8080) |
| `APP_HTTP_BIND` | `0.0.0.0` | Host address the app port binds to (`127.0.0.1` behind Caddy) |
| `MARIADB_ROOT_PASSWORD`, `MARIADB_PASSWORD` | generated | Database passwords |
| `MARIADB_DATABASE`, `MARIADB_USER` | `filehost` | Database name and user |
| `DB_PORT` | `3306` | Host port for MariaDB (127.0.0.1, only with `DB_PUBLISH=true`) |
| `DATABASE_URL` | generated | For running the binary on the host; inside Docker the app uses `mariadb:3306` |
| `SITE_NAME` | **required** | Site name (header, titles, footer) |
| `SITE_TAGLINE` | *(empty)* | Line under the site name |
| `PUBLIC_URL` | *(empty)* | Public address of the site, e.g. `https://files.example.com` |
| `DOWNLOAD_BASE_URL` | *(empty)* | Separate host for downloads; blank = relative links |
| `COOKIE_SECURE` | `true` if `PUBLIC_URL` is https | Secure flag on the session cookie |
| `STORAGE_BACKEND` | `local` | `local`, or `smb` (stub, see [docs/STORAGE.md](docs/STORAGE.md)) |
| `STORAGE_PATH` | `/data/storage` | Storage directory (container path) |
| `INCOMING_PATH` | `/data/incoming` | Incoming folder (container path) |
| `STORAGE_HOST_PATH` | `./data/storage` | Host directory mounted at `STORAGE_PATH` |
| `INCOMING_HOST_PATH` | `./data/incoming` | Host directory mounted at `INCOMING_PATH` |
| `IMPORT_MIN_AGE_SECS` | `30` | Files changed more recently are "still being copied" |
| `ALLOW_WEB_UPLOAD` | `true` | Enable browser uploads (small files) |
| `MAX_UPLOAD_BYTES` | `90000000` | Max browser upload request size (under Cloudflare's ~100 MB cap) |
| `ALLOW_REGISTRATION` | `false` | Initial value of "Allow account requests" (then set in /admin/settings; see [docs/MEMBERS.md](docs/MEMBERS.md)) |
| `TORRENT_ENABLED` | `false` | `.torrent` route: 404 when false, 501 (stub) when true |
| `TORRENT_TRACKERS` | *(empty)* | Comma-separated announce URLs (future) |
| `TORRENT_PIECE_LENGTH` | `4194304` | Torrent piece size, power of two (future) |
| `SIGN_CHECKSUMS` | `false` | Serve the admin-made `SHA256SUMS.asc` ([docs/VERIFYING.md](docs/VERIFYING.md)); 404 when false |
| `STRIP_METADATA` | `false` | Metadata stripping for images/PDFs (stub, see [docs/SANITIZE.md](docs/SANITIZE.md)) |
| `EXTERNAL_MIRRORS_ENABLED` | `false` | Show approved mirror/torrent links publicly (admin toggle wins once saved) |
| `TORRENT_DHT_ENABLED` | `false` | Future generated torrents public (DHT/PEX) instead of private |
| `MIRROR_DISCOVERY_ENABLED`, `FEDERATION_ENABLED` | `false` | Stubs: no routes, no network calls |
| `VPN_SERVICE_PROVIDER`, `VPN_TYPE`, `OPENVPN_USER`, `OPENVPN_PASSWORD`, `WIREGUARD_PRIVATE_KEY`, `WIREGUARD_ADDRESSES`, `SERVER_COUNTRIES`, `VPN_PORT_FORWARDING` | *(empty)*, `openvpn`, ..., `on` | gluetun settings for the `seeder` profile |
| `QBT_WEBUI_PORT` | `8081` | Host loopback port of the qBittorrent Web UI (`seeder`) |
| `QBT_USERNAME`, `QBT_PASSWORD` | `admin`, generated | qBittorrent Web UI login (`seeder`) |
| `QBT_CONFIG_HOST_PATH` | `./data/qbittorrent` | qBittorrent config directory (`seeder`) |
| `QBT_URL` | *(empty)* | For the future in-app seeder integration; unused |
| `SESSION_IDLE_TIMEOUT_MINS`, `SESSION_ABSOLUTE_TIMEOUT_HOURS` | `30`, `12` | Session lifetime |
| `ARGON2_MEMORY_KIB`, `ARGON2_ITERATIONS`, `ARGON2_PARALLELISM` | `19456`, `2`, `1` | Password hashing (OWASP) |
| `TOTP_ENABLED`, `TOTP_ENCRYPTION_KEY` | `false`, generated | Optional 2FA; key encrypts TOTP secrets |
| `TRUSTED_PROXIES`, `CLIENT_IP_HEADER` | loopback + `172.16.0.0/12`, `x-forwarded-for` | Who may set forwarded headers ([HARDENING](docs/HARDENING.md)) |
| `ADMIN_ALLOWED_CIDRS`, `ADMIN_HOST` | *(empty)* | Opt-in: admin only from these IPs / on this host |
| `SETUP_ENABLED` | `true` (install.sh sets `false` once an admin exists) | `/setup` availability |
| `HSTS_ENABLED`, `HSTS_INCLUDE_SUBDOMAINS` | `false` | Opt-in HSTS |
| `LOG_IP_MODE` | `truncated` | `none` / `truncated` (/24, /48) / `full` |
| `REQUEST_TIMEOUT_SECS`, `RATE_LIMIT_PER_MINUTE` | `30`, `600` | Request time and per-IP request budget |
| `MAX_CONNECTIONS`, `MAX_CONNECTIONS_PER_IP` | `1024`, `64` | Connection caps |
| `DOWNLOAD_MAX_CONCURRENT`, `DOWNLOAD_MAX_PER_IP` | `64`, `4` | Concurrent downloads |
| `IMPORT_CONCURRENCY`, `STORAGE_MIN_FREE_BYTES` | `1`, `1G` | Hashing jobs at once; free-space reserve |
| `VERIFY_PROXY_URL` | *(empty)* | Proxy for mirror Verify |
| `APP_MEMORY_LIMIT`, `APP_CPUS`, `APP_PIDS_LIMIT` | `1g`, `2`, `256` | App container limits |
| `DB_PUBLISH` | `false` | Publish MariaDB on 127.0.0.1:`DB_PORT` |
| `RUST_LOG` | `info,sqlx=warn` | Log filter |

`SMB_HOST`, `SMB_SHARE`, `SMB_USERNAME`, `SMB_PASSWORD`, `SMB_DOMAIN` are
documented for the future SMB backend and not read today.

## Large files: the incoming folder

Reverse proxies and tunnels limit request bodies and request time (Cloudflare:
about 100 MB and 100 seconds), so multi-GB browser uploads cannot work behind
them. Instead:

1. Copy the files into the incoming folder, folders included, e.g.
   `rsync -avP --partial-dir=.rsync-partial sources-v0.1.0/ USER@SITEHOST:/data/incoming/sources/`
   (up to 3 folder levels; use your `INCOMING_HOST_PATH`).
2. In /admin, open the release's **Files** page and click **Import all** (or
   **Import all in sources/**, or **Import** on one file), or from a shell:
   `docker compose exec app /app/filehost import --release <project>/<version> [folder]`.
3. Files are imported one at a time in the background (hash, then move into
   storage), keeping their paths: `sources/a.tar.gz` stays `sources/a.tar.gz`
   in the file list, its URL and `SHA256SUMS`. The batch page shows progress
   and a result per file.

Existing paths are never overwritten, and files already imported with the
same SHA-256 are skipped, so an import can simply be run again. Details,
permissions, free space and tips: [docs/IMPORT.md](docs/IMPORT.md).

## Checksums

Every file gets SHA-256 and SHA-512, computed together in one streaming pass
when it is imported or uploaded. Files are stored byte-for-byte (see
[docs/SANITIZE.md](docs/SANITIZE.md)), so the hashes match the upstream
originals. Verification files are generated from the database on each request:

| URL | Content |
|---|---|
| `/p/<slug>/<version>/SHA256SUMS` | `<sha256>  <path>` for every ready file of the release, e.g. `sources/a.tar.gz` |
| `/p/<slug>/<version>/SHA512SUMS` | same with SHA-512 (files without one are left out) |
| `/p/<slug>/<version>/files.json` | path, size, SHA-256, SHA-512 and URL of every file |
| `/download/<id>/sha256`, `/download/<id>/sha512` | the single line for one file |

```bash
curl -fLO https://<site>/p/<slug>/<version>/<file>.iso
curl -fLO https://<site>/p/<slug>/<version>/SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS     # from the folder you downloaded into
```

See [docs/VERIFYING.md](docs/VERIFYING.md) for signatures, folders and
fetching a whole release with `files.json`.

Files from before SHA-512 was added show "n/a"; **Recompute hashes** on the
admin Files page backfills it. Recomputing re-reads the stored file in the
background. If the size or the SHA-256 no longer matches what was recorded,
the file is marked **failed** instead (that means the stored copy changed, so
re-import it).

## External sharing

Everything here is **off by default**. With all toggles off, the app makes no
outbound requests (the only one it ever makes is an admin's explicit mirror
**Verify**) and opens no torrent ports.

- **Mirrors** ([docs/MIRRORS.md](docs/MIRRORS.md)): per-file links to copies
  on Archive.org, GitHub Releases or other servers, added by the admin
  (quick-add helpers build Archive.org/GitHub URLs without any network call),
  optionally verified by hash, shown publicly only when **Show approved
  mirrors** is on in /admin/settings. Pending, rejected and failed mirrors
  never show.
- **Torrents** ([docs/TORRENTS.md](docs/TORRENTS.md)): generation is a stub
  (`/download/<id>/torrent` is 404 unless `TORRENT_ENABLED`, then 501). An
  Archive.org item torrent linked as a mirror is the no-exposure option today.
- **VPN seeder** (`seeder` profile, advanced): qBittorrent runs only inside a
  gluetun VPN container with a firewall kill switch, storage read-only, Web
  UI on 127.0.0.1. Run `scripts/check-seeder-ip.sh` after any change.
  Turn it on or off on a running install with `scripts/enable-seeder.sh` /
  `scripts/disable-seeder.sh` ([docs/TORRENTS.md](docs/TORRENTS.md#enabling-or-disabling-the-seeder-after-install)).
  **Cloudflare Tunnel does not hide BitTorrent traffic.**

## Reverse proxies

The app honors `X-Forwarded-For` and `X-Forwarded-Proto` only from peers in
`TRUSTED_PROXIES` (default: loopback and Docker's bridge range), for logging,
rate limiting and HTTPS detection. Proxies on other machines must be added;
see [docs/HARDENING.md](docs/HARDENING.md#client-ips-and-trusted-proxies).

### NGINX Proxy Manager / Cloudflare Tunnel

Point the proxy host (or tunnel ingress) at `http://<host-ip>:<HTTP_PORT>` and
terminate HTTPS there. **Uploads through the proxy are only for small files**
(`MAX_UPLOAD_BYTES`, default 90 MB). Large files go through `INCOMING_PATH`
(above), so no `client_max_body_size` changes are needed.

For long downloads, this optional NGINX Proxy Manager **Advanced** snippet
streams files instead of spooling them to the proxy's disk:

```nginx
proxy_buffering off;
proxy_read_timeout 3600s;
proxy_send_timeout 3600s;
```

### Caddy

With `COMPOSE_PROFILES=caddy`, Caddy publishes ports 80/443 and proxies to the
app. With a public domain it uses Let's Encrypt automatically (ports 80 and 443
must be reachable from the internet). Without one, it uses its internal CA, and
browsers warn until you trust Caddy's root certificate:

```bash
docker compose exec caddy cat /data/caddy/pki/authorities/local/root.crt > caddy-root.crt
```

Import `caddy-root.crt` as a trusted root CA on each client (Windows:
`certlm.msc` → Trusted Root Certification Authorities; Linux:
`/usr/local/share/ca-certificates/` + `update-ca-certificates`; Firefox has
its own certificate store). Caddy's certificate data lives in the `caddy_data`
volume, so the root stays the same across restarts. See `Caddyfile.example`.

## Downloads behind Cloudflare

Scripted downloads must never get a Cloudflare challenge page. Bot Fight
Mode, "I'm Under Attack" mode, Browser Integrity Check and challenge or rate
limiting rules must stay off (or be skipped) for `/p/` and `/download/`; the
exact settings, a check command, and how to move downloads off the tunnel
(Cloudflare R2, set up in Admin, Storage, or a direct download hostname)
without changing any URL are in [docs/DOWNLOADS.md](docs/DOWNLOADS.md).

## A separate download hostname

Downloads can be served from a different hostname (say `dl.example.com`) than
the site, e.g. to route big transfers differently from the HTML pages. The
same app serves both: `/download/{id}` needs no cookies or session and works
under any `Host` header.

1. Point the second hostname at the same app: a DNS-only (unproxied) record to
   your server plus a proxy host in NPM or Caddy for `dl.example.com` →
   `http://<host-ip>:<HTTP_PORT>`, or a second hostname/ingress rule in your
   tunnel config pointing at the same service.
2. Set **Download base URL** in /admin/settings (or `DOWNLOAD_BASE_URL` in
   `.env`) to `https://dl.example.com`. Every download link on the site now
   points there; no template changes are involved.

> **Cloudflare:** Cloudflare's terms have historically restricted serving
> large amounts of non-HTML content (such as big binary downloads) through its
> proxy and CDN on standard plans. Check the current terms before routing
> large downloads through Cloudflare; a DNS-only download hostname avoids the
> question.

## Backups

`scripts/backup.sh` dumps the database and archives the configuration
(owner-only files, optionally encrypted); see [docs/BACKUP.md](docs/BACKUP.md)
for storage backups and restores. The manual equivalent:

```bash
# Database (runs inside the MariaDB container)
docker compose exec -T mariadb sh -c \
  'mariadb-dump -uroot -p"$MARIADB_ROOT_PASSWORD" --single-transaction "$MARIADB_DATABASE"' \
  > backup-$(date +%F).sql

# Files (STORAGE_HOST_PATH, ./data/storage by default)
sudo rsync -a ./data/storage/ /backups/<site-name>-storage/
```

Restore: `docker compose exec -T mariadb sh -c 'mariadb -uroot -p"$MARIADB_ROOT_PASSWORD" "$MARIADB_DATABASE"' < backup.sql`
and copy the storage folder back (owned by UID/GID 10001). Also keep a copy of
`.env`. Without it the database passwords are lost.

## Upgrading

1. **Back up first**: `scripts/backup.sh` (database + configuration) and a
   copy of the storage folder (see [docs/BACKUP.md](docs/BACKUP.md)). New
   versions may add database migrations, which run automatically at startup
   and cannot be undone by downgrading.
2. `git pull`
3. `./install.sh`: asks only about settings that are new, appends new
   defaults, rebuilds and restarts. (`docker compose up -d --build` does the
   rebuild/restart alone if nothing in `.env` needs adding.)
4. Check the commit history for notes on what changed.

## Security

- [docs/SECURITY-REVIEW.md](docs/SECURITY-REVIEW.md): findings and fixes.
- [docs/HARDENING.md](docs/HARDENING.md): trusted proxies (Cloudflare Tunnel,
  NPM), ADMIN_HOST + Cloudflare Access, 2FA and lockout recovery, HSTS,
  cloudflared, container hardening, secret rotation.
- [docs/PRIVACY.md](docs/PRIVACY.md): what is collected, logged and sent where.
- [docs/VERIFYING.md](docs/VERIFYING.md): checking signatures and checksums
  (and signing releases without keys on the server).
- [SECURITY.md](SECURITY.md): reporting vulnerabilities.

The admin password can be changed at /admin/password; optional TOTP 2FA is
at /admin/2fa (with `TOTP_ENABLED=true`). Locked out of 2FA:
`docker compose exec app /app/filehost admin reset-2fa`. Members use
/my/password and /my/2fa; the admin can reset either for them under Users.

Since the hardening release MariaDB has **no host port** by default; set
`DB_PUBLISH=true` and re-run `./install.sh` if a host tool needs it.

## Development

```bash
docker compose up -d mariadb            # with DB_PUBLISH=true: database on 127.0.0.1:$DB_PORT
STORAGE_PATH=./data/dev-storage INCOMING_PATH=./data/dev-incoming cargo run
# LISTEN_ADDR=127.0.0.1:8090 cargo run  # if 8080 is taken (Docker always uses 8080)
cargo fmt --check && cargo clippy --all-targets --all-features -- -D warnings
cargo test                              # unit tests
TEST_DATABASE_URL=mysql://root:<root-password>@127.0.0.1:<DB_PORT>/filehost_test cargo test   # + database tests
cargo test -- --ignored                # network tests: mirror Verify against a real public file,
                                        # and R2 against a local S3 server (needs R2_ENDPOINT_OVERRIDE,
                                        # R2_SIGNING_REGION=us-east-1, R2_TEST_KEY/_SECRET/_BUCKET; see src/r2.rs)
python3 tests/browser/flow.py http://localhost:8080   # real-browser flow (Playwright), FRESH site only
```

The database tests (`tests/integration.rs`, `tests/security.rs`,
`tests/members.rs`, `tests/releases.rs`) drive the full router against a real MariaDB. They
**wipe the database they are given**, so use a dedicated one. Without
`TEST_DATABASE_URL` they skip. Queries are runtime-checked
(`sqlx::query`), so building never needs a database. Migrations in
`migrations/` are embedded and applied at startup.

## Project layout

```
src/
  main.rs            CLI entry (serve, `import`, `admin reset-2fa`, `healthcheck`)
  lib.rs             module list, server startup
  config.rs          env parsing and validation
  state.rs           AppState, download URL helpers
  settings.rs        site settings (env seeding, admin overrides)
  routes/            public.rs (pages, stable URLs, latest, files.json),
                     auth.rs (setup, register, login, roles),
                     admin.rs (admin + member workspace), members.rs (users,
                     review, limits), account.rs, mod.rs (router, middleware)
  importer.rs        bulk imports: batches, duplicates, skips, free space
  r2.rs              optional Cloudflare R2 copy: S3 SigV4 client, sync job
  tree.rs            release files as a folder tree for the templates
  db/                models.rs, queries.rs, mod.rs (pool + migrations)
  storage/           mod.rs (StorageBackend trait), local.rs, smb.rs (stub)
  incoming.rs        incoming-folder scan and path validation
  hashing.rs         SHA-256 + SHA-512 in one streaming pass
  checksums.rs       SHA256SUMS / SHA512SUMS format
  sanitize.rs        metadata-stripper trait and registry (stub, empty)
  mirrors.rs         mirror URL validation, quick-add builders, SSRF-safe Verify
  guard.rs           rate limit, admin gate, Origin check, timeouts, HSTS
  limits.rs          connection/download caps, free-space check
  fsid.rs            file identity pinning for imports (TOCTOU)
  totp.rs            TOTP, recovery codes, secret encryption, QR SVG
  integrity.rs       background storage integrity check
  net.rs             trusted proxies, client IP, IP truncation for logs
  seeder.rs          Seeder trait (stub) and qBittorrent client skeleton
  torrent.rs         .torrent generation stub
  range.rs net.rs ratelimit.rs markdown.rs util.rs views.rs error.rs
templates/           Askama templates (base.html layout, admin/, my/)
static/style.css     the theme, embedded in the binary
migrations/          SQL migrations
scripts/             set-site-name.sh, set-download-url.sh, check-seeder-ip.sh,
                     enable-seeder.sh, disable-seeder.sh, backup.sh,
                     lib/env.sh, lib/qbittorrent.sh, lib/seeder-setup.sh
docs/                IMPORT.md, STORAGE.md, MIRRORS.md, SANITIZE.md, TORRENTS.md,
                     FUTURE.md, SECURITY-REVIEW.md, HARDENING.md, PRIVACY.md,
                     VERIFYING.md, BACKUP.md, MEMBERS.md, DOWNLOADS.md
tests/               integration.rs, security.rs, members.rs, releases.rs (database),
                     browser/flow.py (headless Chromium)
```

## Design notes and simplifications

Where the requirements left room, the simplest option was chosen:

- Crate and binary are called `filehost`; nothing carries a site or brand name.
- **Env vs. admin settings:** `.env` values apply until overridden in
  /admin/settings (per setting); see above.
- **Download counting:** a download is counted for GET requests starting at
  byte 0 (full downloads and first segments), so resumes and segmented
  downloaders don't inflate counts. HEAD requests are not counted.
- **Filenames** are sanitized to a conservative ASCII set (other characters
  become `_`); files are stored under random UUID keys, never their names.
- **Imports copy between the two bind mounts:** `rename()` cannot cross mount
  points, even on one disk, so with separate `storage` and `incoming` mounts an
  import copies and then deletes the original. [docs/IMPORT.md](docs/IMPORT.md)
  shows a single-mount override that makes imports an instant rename.
- **Login rate limit:** per client IP and per username, in memory; after 5
  failures each further one doubles a lockout (30 s up to 15 min). Sessions
  end after 30 minutes idle or 12 hours, whichever comes first.
- **`MAX_UPLOAD_BYTES`** applies to a whole upload request (all files in it).
- **Recompute hashes** marks a file failed when its SHA-256 changed, not
  just when its size did: silently publishing a new checksum would hide
  corruption.
- During a recompute the file is briefly not downloadable (status `hashing`);
  a recompute interrupted by a restart simply returns the file to `ready`.
- **`files.status` also has `hashing`** (beyond importing/ready/failed): it
  marks a file whose hashes are being recomputed, so it is briefly hidden like
  any non-ready file. It was added by an earlier migration and is kept rather
  than removed by a destructive one.
- **Mirror Verify** treats a successful check of a previously failed mirror
  as `pending`, not `approved`: the admin re-approves deliberately.
- **Migrated mirrors:** the old single `mirror_url` per file became an
  approved admin mirror in `file_mirrors` (label = host name). They are only
  shown publicly while `EXTERNAL_MIRRORS_ENABLED` is on.
- **`STORAGE_BACKEND=smb`** starts but logs a warning; every file operation
  fails with "not implemented".
- Forwarded headers are trusted only from `TRUSTED_PROXIES`; from any other
  peer they are ignored.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security problems: please report them
privately as described in [SECURITY.md](SECURITY.md).

## License

Copyright (C) 2026 the Abyssal Archives contributors

This program is free software: you can redistribute it and/or modify it
under the terms of the GNU Affero General Public License as published by the
Free Software Foundation, either version 3 of the License, or (at your
option) any later version. See [LICENSE](LICENSE).

The AGPL also covers network use: if you run a modified version as a public
service, you must offer its users the corresponding source code.
