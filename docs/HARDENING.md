# Deployment hardening

The defaults are safe for a site behind a reverse proxy. This guide covers
the settings that depend on your deployment. Findings and fixes:
[SECURITY-REVIEW.md](SECURITY-REVIEW.md). What is collected:
[PRIVACY.md](PRIVACY.md).

## Client IPs and trusted proxies

The app sees the TCP peer of each connection. Behind a proxy that peer is
the proxy, and the real client is in a forwarded header. The app honors
`X-Forwarded-For`, `X-Forwarded-Proto` (and optionally `CF-Connecting-IP`)
**only when the peer is in `TRUSTED_PROXIES`**; otherwise it uses the socket
address, so nobody can spoof their IP to dodge rate limits or pollute logs.

`TRUSTED_PROXIES` (default `127.0.0.0/8,::1/128,172.16.0.0/12`: loopback and
Docker's default bridge range) is a comma-separated CIDR list. With
`X-Forwarded-For` the app walks the list from the right, skips addresses of
trusted proxies, and takes the first untrusted one. That is correct for
chains of proxies.

| Setup | What to set |
|---|---|
| Bundled Caddy | defaults (Caddy is on the Docker network) |
| NPM in Docker on this host | defaults |
| NPM on another machine (e.g. `192.168.1.20`) | add it: `TRUSTED_PROXIES=127.0.0.0/8,::1/128,172.16.0.0/12,192.168.1.20/32` |
| Docker networks from `192.168.0.0/16` pools | add those subnets (`docker network inspect <project>_frontend`) |
| Cloudflare Tunnel → NPM → app | defaults if cloudflared and NPM run in Docker on this host (both trusted, skipped); the client is the address Cloudflare put in `X-Forwarded-For` |
| Cloudflare Tunnel → app directly | defaults, or `CLIENT_IP_HEADER=cf-connecting-ip` |

`CLIENT_IP_HEADER=cf-connecting-ip` trusts Cloudflare's header instead.
**Only use it when the origin is reachable exclusively through Cloudflare**
(tunnel, no open ports); otherwise anyone reaching a trusted proxy directly
could set it.

**Docker port-publishing caveat.** Connections to a published port that go
through Docker's userland proxy (from the host itself, or over IPv6) reach
the container from the bridge gateway (`172.x.0.1`), which is in the default
trusted range. So **do not expose the app's port to untrusted networks**: put
it behind the proxy and bind it to localhost (`APP_HTTP_BIND=127.0.0.1`, set
automatically with the bundled Caddy), or narrow `TRUSTED_PROXIES` to the
proxy's exact address.

## Admin surface

Both settings below protect **the administrator**, not the sign-in page:
`/login`, `/register` and the member area (`/my`) work on any host and from
any address, because members sign in there (docs/MEMBERS.md). What they
guard:

- the `/admin` pages and `/setup` (404 elsewhere);
- signing in as the administrator: with the right password from a wrong
  host or address, the answer is the same "Invalid username or password" as
  for a wrong password (the server log says why);
- the administrator's session: a session cookie used from elsewhere is
  worthless (404).

- `ADMIN_HOST=admin.example.com`: the above only on that host name. Route
  that name to the same app (DNS-only record or a second tunnel/NPM host)
  and put **Cloudflare Access** (Zero Trust → Access → Applications →
  self-hosted, host `admin.example.com`, policy: your e-mail / identity
  provider) in front of it. Access sits outside the app and adds a login
  before anyone reaches the app's own login. The public footer's "Login"
  link points at the public host's `/login` (for members) and never reveals
  the admin host.
- `ADMIN_ALLOWED_CIDRS=10.0.0.0/8,192.168.1.0/24`: the above only from those
  client addresses (as resolved above). Good with a VPN or LAN. Keep a way
  in: a wrong value locks you out of the web admin (fix `.env` and
  `docker compose up -d app`).
- `SETUP_ENABLED`: install.sh sets it to `false` on its next run after the
  admin exists. `/setup` is also impossible whenever any user exists.
- Admin, member, sign-in and registration pages are sent with
  `Cache-Control: no-store` and `Referrer-Policy: same-origin`.

## Sessions, passwords, 2FA

- Session cookie: `__Host-sid` (Secure, HttpOnly, SameSite=Strict, Path=/)
  when `COOKIE_SECURE=true`; idle timeout `SESSION_IDLE_TIMEOUT_MINS` (30),
  absolute `SESSION_ABSOLUTE_TIMEOUT_HOURS` (12). Rotated on every login;
  logout deletes it server-side.
- Passwords: Argon2id, OWASP parameters by default (`ARGON2_MEMORY_KIB=19456`,
  `ARGON2_ITERATIONS=2`, `ARGON2_PARALLELISM=1`). Raising them upgrades each
  stored hash at the next login. Change the password at /admin/password
  (members: /my/password; ends all other sessions).
- Login limits: per client IP and per username. After 5 failures each
  further failure doubles a lockout from 30 s up to 15 min.
- **TOTP 2FA (opt-in)**: set `TOTP_ENABLED=true` (install.sh already created
  `TOTP_ENCRYPTION_KEY`), `docker compose up -d app`, then /admin/2fa. Save
  the 10 recovery codes offline. **Locked out?**
  `docker compose exec app /app/filehost admin reset-2fa` turns 2FA off (and
  ends sessions); sign in with the password and enrol again. Never change
  `TOTP_ENCRYPTION_KEY` while 2FA is enrolled: secrets could no longer be
  decrypted (the reset command recovers from that too).

## HTTPS and HSTS

`HSTS_ENABLED=true` adds `Strict-Transport-Security: max-age=31536000` (add
`HSTS_INCLUDE_SUBDOMAINS=true` only if every subdomain serves HTTPS) when
`COOKIE_SECURE=true` and a trusted proxy reports `X-Forwarded-Proto: https`.
Off by default because it cannot be undone quickly in browsers. Behind
Cloudflare → NPM, NPM usually reports the scheme of its own hop (often
`http` from cloudflared), so enable HSTS at Cloudflare instead (SSL/TLS →
Edge Certificates → HSTS).

The bundled Caddy's generated Caddyfile removes its `Server` header; for an
existing Caddyfile add `header -Server` inside the site block.

## Cloudflare Tunnel (cloudflared)

Run cloudflared as a container next to the stack, with its token in a
**separate env file that is never committed**:

```bash
printf 'TUNNEL_TOKEN=%s\n' '<token from the Cloudflare dashboard>' > cloudflared.env
chmod 600 cloudflared.env        # .env.* style files are git-ignored; this name is too (see .gitignore)
```

`docker-compose.override.yml` (git-ignored):

```yaml
services:
  cloudflared:
    image: cloudflare/cloudflared:<pinned version>
    command: tunnel --no-autoupdate run
    env_file: cloudflared.env
    restart: unless-stopped
    networks: [frontend]
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
```

Point the tunnel's public hostname at `http://app:8080` (or at NPM). Then
the origin needs **no open ports and no port forwards**: bind the app to
localhost (`APP_HTTP_BIND=127.0.0.1`) or remove its published port, and
close 80/443 on the router. Remember: the tunnel carries HTTP only and does
not hide BitTorrent traffic (docs/TORRENTS.md).

## Containers

- app: distroless image (no shell), UID/GID 10001, read-only root file
  system with a small `/tmp` tmpfs, all capabilities dropped,
  `no-new-privileges`, limits `APP_MEMORY_LIMIT` (1g), `APP_CPUS` (2),
  `APP_PIDS_LIMIT` (256); files 0600 / directories 0700 (umask 077).
- MariaDB: on an internal-only network with the app; no host port unless
  `DB_PUBLISH=true` (then 127.0.0.1 only); the app connects as
  `MARIADB_USER`, never root.
- Caddy: only `NET_BIND_SERVICE`, `no-new-privileges`.
- Seeder: only gluetun has `NET_ADMIN`; qBittorrent keeps just the
  capabilities its init needs to drop to UID 10001, `no-new-privileges`,
  storage mounted read-only, Web UI on 127.0.0.1 only.
- Every image is pinned by digest; Dependabot proposes updates weekly.

## Abuse limits

`RATE_LIMIT_PER_MINUTE` (600 per client IP), `DOWNLOAD_MAX_CONCURRENT` (64)
and `DOWNLOAD_MAX_PER_IP` (4; segmented download managers may need more),
`MAX_CONNECTIONS` (1024) and `MAX_CONNECTIONS_PER_IP` (64; trusted proxies
only count globally), 10 s to send request headers, 64 KiB request bodies
outside uploads, `REQUEST_TIMEOUT_SECS` (30) for everything except
downloads/uploads, one `Range` per request, `IMPORT_CONCURRENCY` (1) hashing
jobs at a time, `STORAGE_MIN_FREE_BYTES` (1G) kept free.

## Rotating secrets

If `.env` (or a backup of it) was exposed:

- `MARIADB_PASSWORD`: `docker compose exec mariadb sh -c 'mariadb -uroot -p"$MARIADB_ROOT_PASSWORD" -e "ALTER USER \"$MARIADB_USER\"@\"%\" IDENTIFIED BY \"<new>\""'`,
  update `.env` (`MARIADB_PASSWORD`, `DATABASE_URL`), `docker compose up -d app`.
- `MARIADB_ROOT_PASSWORD`: same with `ALTER USER 'root'@'%'` and `'root'@'localhost'`.
- `TOTP_ENCRYPTION_KEY`: run `admin reset-2fa`, replace the key
  (`openssl rand -base64 32`), restart, re-enrol.
- `QBT_PASSWORD`: `scripts/disable-seeder.sh` (remove credentials), then
  `scripts/enable-seeder.sh` (generates a new one and updates qBittorrent).
- VPN credentials: rotate at the provider, update `.env`, `docker compose up -d gluetun qbittorrent`.
- The admin password: /admin/password.
