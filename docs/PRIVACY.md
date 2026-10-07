# Privacy

What this application collects, stores, logs, and sends elsewhere, in plain
language. "The operator" is whoever runs this site.

## Visitors (anyone downloading files)

- **No cookies.** Public pages and downloads never set a cookie.
- **No accounts, sessions, analytics, tracking pixels, fonts or CDNs.**
  Every page, stylesheet and image comes from this server; the site ships no
  JavaScript at all.
- **Nothing per visitor is stored in the database.** The only thing a
  download changes is an aggregate counter (`download_count`) on the file.
  There is no table of who downloaded what.
- **Images in project descriptions** can only come from this site; links to
  images on other servers are removed, because loading them would tell those
  servers your IP address.
- **Links to other sites** (mirrors, links in descriptions) carry
  `rel="noopener noreferrer nofollow"` and public pages send
  `Referrer-Policy: no-referrer`, so the other site is not told which page you
  came from. (The admin and login pages use `same-origin`: the browser then
  tells only this site where a form was submitted from, which the CSRF
  protection needs, and still tells other sites nothing.) **Clicking a mirror or torrent link takes you to that host**, which
  then sees your IP address like any website you visit.

## Logs

- Each request is logged with method, path (never the query string), status
  and timing, plus the client's address according to `LOG_IP_MODE`:
  - `truncated` (default): IPv4 /24, IPv6 /48 (e.g. `203.0.113.0/24`), which is
    enough to spot abuse without identifying a person;
  - `none`: no address at all;
  - `full`: the complete address.
- Failed logins and rate-limit hits are logged with the same truncated
  address. **Passwords, usernames typed at login, cookies, session tokens,
  CSRF tokens and query strings are never logged.**
- Logs go to the container's standard output (`docker compose logs app`).
  **Retention is up to the operator**: Docker's default `json-file` driver
  keeps logs until the container is removed. Set rotation in
  `/etc/docker/daemon.json`, e.g.
  `{"log-driver":"json-file","log-opts":{"max-size":"10m","max-file":"5"}}`,
  and keep only what you need.
- Rate limiting keeps recent client addresses **in memory only** (never on
  disk), forgotten after at most 24 hours or on restart.

## Accounts (the administrator and members)

- Per account: username, Argon2id password hash, role and state (pending,
  active, disabled), and (if 2FA is used) the TOTP secret **encrypted** with
  a key kept outside the database (`TOTP_ENCRYPTION_KEY`) plus hashed
  recovery codes.
- Account requests (/register, only when the admin allows them) store the
  username, password hash and the optional note the applicant writes for the
  admin. **No e-mail address is asked for and no e-mail is ever sent**: the
  applicant learns the outcome by signing in. A rejected request is deleted.
- Members' upload limit / quota overrides and their requests for more (the
  values asked for, the reason they give, the admin's decision and note).
- Deleting a member deletes their account, projects and files.
- Sessions: only a SHA-256 hash of the session token is stored, with
  creation/last-activity times and expiry. Expired sessions are deleted.
- The admin pages are never cached (`Cache-Control: no-store`).

## What leaves the server

**Nothing**, unless you use one of these opt-in features:

| Feature | What goes out | To whom |
|---|---|---|
| Mirror **Verify** (admin click) | one HTTP(S) download of the mirror URL; reveals this server's IP (or the `VERIFY_PROXY_URL` proxy's) | the mirror host |
| **Seeder** profile (qBittorrent behind a VPN) | BitTorrent traffic for torrents you add | peers, via your VPN provider |
| Caddy with a domain | ACME certificate requests | Let's Encrypt |

The app never phones home, checks for updates, or contacts Archive.org,
GitHub or any other service on its own. Mirror discovery and federation are
off and not implemented.

## Backups

`scripts/backup.sh` writes the database and configuration (owner-only
files, optionally encrypted with `age` or `gpg`). The database contains no
visitor data beyond aggregate download counts; it does contain the account
data listed above.
