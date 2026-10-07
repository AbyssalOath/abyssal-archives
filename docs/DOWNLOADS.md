# Download URLs, Cloudflare and where downloads are served from

## Stable URLs

| URL | What |
|---|---|
| `/p/<project>` | project page: description, releases, main downloads |
| `/p/<project>/<version>` | release page: notes, main downloads first, folders collapsed |
| `/p/<project>/<version>/<path>` | **the file itself**, e.g. `.../v0.1.0/sources/a.tar.gz` |
| `/p/<project>/<version>/SHA256SUMS`, `SHA512SUMS` | checksums of every file, by path |
| `/p/<project>/<version>/SHA256SUMS.asc` | detached signature, when published (docs/VERIFYING.md) |
| `/p/<project>/<version>/files.json` | path, size, SHA-256, SHA-512 and URL of every file |
| `/p/<project>/latest` | redirects to the newest published release's page |
| `/p/<project>/latest/download` | redirects (once) to that release's **recommended** file |
| `/download/<id>` | older per-file links; keep working |

File URLs are plain `GET`s: no tokens, no cookies, no JavaScript, no
redirects. They answer `200` with `Content-Type: application/octet-stream`,
the exact `Content-Length`, `Accept-Ranges: bytes` and an `attachment`
`Content-Disposition` with the file name; `Range` requests (resume,
segmented downloads) get `206 Partial Content`. `HEAD` works too.

```bash
curl -fLO  https://abyssaloath.com/p/abyssal-sanctum/v0.1.0/abyssal-sanctum-v0.1.0-secureboot.iso
curl -C - -O https://abyssaloath.com/p/abyssal-sanctum/v0.1.0/abyssal-sanctum-v0.1.0-secureboot.iso   # resume
wget -c    https://abyssaloath.com/p/abyssal-sanctum/v0.1.0/abyssal-sanctum-v0.1.0-secureboot.iso
curl -r 0-99 -o head.bin https://abyssaloath.com/p/abyssal-sanctum/v0.1.0/sources/a.tar.gz           # 206, 100 bytes

# always the newest recommended file (one redirect; -J / --content-disposition keep the real name)
curl -fLOJ https://abyssaloath.com/p/abyssal-sanctum/latest/download
wget --content-disposition https://abyssaloath.com/p/abyssal-sanctum/latest/download
```

A URL keeps pointing at the same bytes: paths in a release are never
overwritten (delete and re-import to replace a file; the deletion is
logged). "latest" is reserved and cannot be used as a version name.

**Recommended file:** on the release's Files page in the admin, **Mark
recommended** on one file (for Sanctum, the `-secureboot.iso`). It is shown
first with a "Recommended" badge, gets a big download button on the release
page, and is what `/latest/download` serves. A release without one makes
`/latest/download` answer 404 with an explanation.

**Unpublishing** a release (Publishing box on its Files page) makes all of
the URLs above answer 404 for it, but keeps every file; publishing it again
brings the same URLs back. Releases and files that are published can only be
deleted by typing their version or path, and every deletion is logged
(Admin, **Log**).

## Cloudflare: keep scripted downloads from being challenged

When the site is behind Cloudflare (Tunnel or proxied DNS), Cloudflare can
answer a request itself with a challenge page (HTML, status 403 or 503,
header `cf-mitigated: challenge`) instead of passing it to the app. Browsers
can solve that; `curl`, `wget`, package scripts and download managers cannot,
and would save the challenge page as the file. Settings in the Cloudflare
dashboard for the zone:

| Setting | Where | What to do |
|---|---|---|
| **Bot Fight Mode** | Security, Bots | **Off.** On the Free plan it applies to the whole zone and cannot be skipped by rules, and it challenges command-line clients |
| Super Bot Fight Mode (Pro and up) | Security, Bots | "Definitely automated" and "Verified bots": **Allow**, or skip it for the paths below with a WAF rule |
| **Security Level / "I'm Under Attack" mode** | Security, Settings | Never "I'm Under Attack" for the download paths (it challenges every visitor); if you need it for the site, add a Configuration Rule for the paths below that sets the security level lower |
| **Browser Integrity Check** | Security, Settings | Turn it off for the download paths with a Configuration Rule (it blocks requests with unusual or missing headers, which some scripts send) |
| **WAF custom rules** | Security, WAF | No Managed Challenge / JS Challenge / Interactive Challenge rule may match the paths below. Put a rule **first** with action **Skip** (remaining custom rules, rate limiting rules, managed rules, Super Bot Fight Mode) for them |
| Rate limiting rules | Security, WAF | Exclude the paths below, or allow far more requests than a mirror script makes (577 files per release) |

The paths (expression for the Skip and Configuration rules):

```
(starts_with(http.request.uri.path, "/p/") or starts_with(http.request.uri.path, "/download/"))
and http.request.method in {"GET" "HEAD"}
```

That covers the project and release pages too, which is harmless (they are
plain HTML without forms). Admin pages are not under these paths.

Caching: Cloudflare caches responses with common download extensions
(`.iso`, `.gz`, `.zip`, ...) by default, up to 512 MB per file on the
Free, Pro and Business plans; bigger files always come from the server.
Because a path never changes its content, caching is safe. Do **not** add a
"Cache Everything" rule that covers `SHA256SUMS`, `SHA512SUMS` or
`files.json` (they change when files are added; the app marks them
`Cache-Control: no-cache`).

Check from outside (another network) after any change:

```bash
curl -sI https://abyssaloath.com/p/abyssal-sanctum/latest/download | grep -iE '^HTTP|^location|cf-mitigated'
curl -sI https://abyssaloath.com/p/abyssal-sanctum/v0.1.0/sources/SHA256SUMS | grep -iE '^HTTP|content-type|cf-mitigated'
# expect 303 + location, then 200 + application/octet-stream, and no cf-mitigated header
```

## Where downloads are served from

By default downloads go **through the Cloudflare Tunnel**: the app serves
every file itself. Cloudflare's terms ask for a paid service (such as R2) to serve
"video and other large files" through its CDN; ISOs and tens of GB of
tarballs per release are that kind of traffic, and Cloudflare may restrict a
zone it thinks breaks the rule. The public URLs above are designed so the
storage behind them can change without breaking any link. Two ways to move
off the tunnel:

### (b) A download hostname that bypasses Cloudflare

1. DNS: `dl.abyssaloath.com` as a **DNS-only** (grey cloud) record to the
   server's public IP; forward port 443 to it.
2. TLS: the bundled Caddy (`COMPOSE_PROFILES=caddy`) gets a Let's Encrypt
   certificate for `dl.abyssaloath.com`, or add a host to your proxy.
3. Admin, Settings, **Download base URL** = `https://dl.abyssaloath.com`
   (or `DOWNLOAD_BASE_URL` in `.env`). Every link on the pages, in
   `files.json` and the target of `/latest/download` now uses
   `https://dl.abyssaloath.com/p/<project>/<version>/<path>`; the same app
   serves it there.
4. Old links to `https://abyssaloath.com/p/<project>/<version>/<path>` still
   work (through the tunnel). To move them too, add a Cloudflare Redirect
   Rule on the main zone for file paths only, e.g. paths with a file
   extension under `/p/`, to `https://dl.abyssaloath.com` + the same path
   (one redirect, status 302).

Costs nothing. It exposes the server's IP address, gives up Cloudflare's
DDoS protection for that hostname, and the server's upload bandwidth limits
every download.

### (a) Cloudflare R2 (built in, optional)

R2 is Cloudflare's object storage, the service their terms point to for
serving large files, with **free egress**: you pay for storage (about $0.015
per GB-month, the first 10 GB free) and requests (downloads about $0.36 per
million, the first 10 million a month free; uploads about $4.50 per million,
the first million free). Check current pricing. A Sanctum release (about
28 GB) costs about $0.42 a month to keep there (less while within the free
10 GB).

How it works here:

- **This server keeps the master copy** of every file (imports, hashing,
  integrity checks, backups, the GPL source archive). R2 holds a copy of
  every **published** file only, under `<project>/<version>/<path>`, so the
  bucket is a readable mirror of the public releases.
- A background job uploads new published files **one at a time**, streamed
  from storage (never loaded into memory). Each upload is signed with the
  file's recorded SHA-256 (files over 4 GiB: in 128 MiB parts, each signed
  with its own SHA-256), so R2 rejects any byte that differs from what was
  imported. Failures are retried every 15 minutes, or at once with **Sync
  now**.
- Unpublishing or deleting a release or file removes its objects from the
  bucket within seconds (the job wakes on every publishing change, deletion
  and import, and checks every minute anyway). R2 objects are public, so
  only published files are ever there.
- With **Serve downloads from R2** on, every stable URL
  (`/p/<project>/<version>/<path>`, `/download/<id>`) answers with **one**
  `302` redirect (never cached) to the R2 copy, once that copy is uploaded;
  files not uploaded yet are still served by this server.
  `/p/<project>/latest/download` redirects straight to the R2 copy (still one
  hop). Range requests, resume and `Content-Length` are handled by R2; the
  objects carry `Content-Type: application/octet-stream` and an `attachment`
  name, like the server's own responses. Downloads are still counted (at the
  redirect).
- Turning serving off, or **Stop using R2**, makes this server serve
  everything again at once. **No public URL changes either way.**

Setup:

1. Cloudflare dashboard, **R2**: subscribe if needed and **create a bucket**
   (e.g. `abyssal-downloads`). Note the **Account ID** (R2 overview, Account
   details) and, if you picked one, the bucket's jurisdiction (EU, FedRAMP).
2. The bucket's **Settings, Custom Domains: connect** a hostname of your
   zone, e.g. `dl.abyssaloath.com`, and wait until it shows Active. Do not
   use the `r2.dev` URL: it is rate-limited and meant for development.
   Leave **public access through r2.dev disabled**.
3. **R2, Manage API tokens, Create API token**: permission **Object Read &
   Write**, applied to **that bucket only**, no expiry or one you will
   remember to renew. Copy the **Access Key ID** and **Secret Access Key**
   (shown once).
4. In this site: **Admin, Storage**. Fill in Account ID, bucket, the two
   keys and the public URL (`https://dl.abyssaloath.com`), click **Test**:
   it uploads a small object, downloads it through the custom domain,
   compares its SHA-256 and deletes it.
5. Tick **Upload published files to R2** and **Save**. Watch the counter
   ("n / m published files on R2"). Your server's upload bandwidth sets the
   pace: a 28 GB release takes about 4 hours at 15 Mbit/s.
6. Once your files are there, tick **Serve downloads from R2** and Save.
   Check from outside:
   `curl -sIL https://abyssaloath.com/p/<project>/<version>/<file> | grep -iE '^HTTP|^location|content-length'`
   should show `302`, a `location` on `dl.abyssaloath.com`, then `200` with
   the right length.

The Cloudflare settings above apply to the custom domain as well (it is in
the same zone): Bot Fight Mode and challenges must not hit
`dl.abyssaloath.com` either. Add it to the Skip rule, e.g.
`(http.host eq "dl.abyssaloath.com") or (...the paths above...)`.

Secrets: the secret access key is stored **encrypted** (AES-256-GCM) in the
database with a key derived from `TOTP_ENCRYPTION_KEY` in `.env`, which is
never in the database or its dumps. It is write-only in the admin page and
never logged. If `TOTP_ENCRYPTION_KEY` changes, enter the secret again.
To rotate the token: create a new one in Cloudflare, paste both keys in
Admin, Storage, Save, then delete the old token.

Stopping: untick **Serve downloads from R2** to serve from this server
again (copies stay and keep syncing), or **Stop using R2** to also forget
the settings. Objects already in the bucket are not deleted by "Stop using
R2" (the site no longer has the key): delete them, or the bucket, in the
dashboard.
