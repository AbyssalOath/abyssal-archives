# Torrents

Two separate things live here:

1. **Torrent generation** by the app: a **stub** today (planned design below).
2. **Self-seeding through a VPN container**: optional, OFF by default, the
   compose profile `seeder` (gluetun + qBittorrent). Advanced and
   experimental; read "Privacy and safety" before enabling it.

The no-exposure alternatives come first, though: an **Archive.org item
torrent linked as a mirror** (docs/MIRRORS.md) gives visitors a torrent with
Archive.org as the seed, and this server is never involved.

## 1. Torrent generation (stub)

What exists:

- `src/torrent.rs`: `generate_torrent(file_path, name, piece_length, trackers, web_seeds)`,
  which returns `TorrentError::NotImplemented`.
- `GET /download/{file_id}/torrent`: **404** while `TORRENT_ENABLED=false`
  (default), a themed **501** when `true`.
- `files.torrent_infohash CHAR(40) NULL`, unused.
- Config: `TORRENT_ENABLED`, `TORRENT_TRACKERS` (comma-separated, empty),
  `TORRENT_PIECE_LENGTH` (default 4 MiB, a power of two), and the admin toggle
  `TORRENT_DHT_ENABLED` (public vs private flag).
- The "Torrent" link for generated torrents is never shown while this is a
  stub. (Approved torrent *mirrors* are separate, see docs/MIRRORS.md.)

### Plan: the "no-exposure torrent"

- Generated **locally** by the app, **single-file**, named after the
  sanitized filename. SHA-1 piece hashes (BitTorrent v1) are computed by
  **streaming** the stored file in `TORRENT_PIECE_LENGTH` chunks, in a
  background job like imports. Results are cached, and the info-hash is
  stored in `files.torrent_infohash`.
- **No tracker, no DHT, no PEX** in this mode: the torrent lists only **web
  seeds** (BEP 19 `url-list`): the file's HTTP download URL built from
  `DOWNLOAD_BASE_URL` (`AppState::download_url_for_torrent`, falling back to
  `PUBLIC_URL`), plus the URLs of **approved http mirrors**. Clients download
  pieces over plain HTTP Range requests, which `/download/{id}` already
  supports. Nobody announces an IP anywhere, and this server is just an HTTP
  server.
- The **private flag** follows `TORRENT_DHT_ENABLED`: off (default) →
  `private=1` (no DHT/PEX); on → public. Trackers from `TORRENT_TRACKERS`
  are added only when the admin deliberately runs the seeder.
- Bencoding: a small hand-written encoder or a vetted crate; hashing with
  RustCrypto `sha1`.

## 2. Self-seeding through a VPN container (profile `seeder`)

`./install.sh` → **External sharing → 3** sets it up (typed "yes" required):
VPN provider and credentials go into `.env`, `QBT_PASSWORD` is generated,
qBittorrent's config is pre-seeded, and `seeder` is added to
`COMPOSE_PROFILES`. To turn it on or off on a running install, see
[Enabling or disabling the seeder after install](#enabling-or-disabling-the-seeder-after-install).

### What runs

- **gluetun** (`qmcgaw/gluetun`, pinned): VPN client with a firewall that is
  on from container start and blocks all traffic unless the VPN is up (kill
  switch). DNS goes through gluetun. Port forwarding is enabled
  (`VPN_PORT_FORWARDING=on`); gluetun then picks port-forwarding servers.
- **qbittorrent** (`linuxserver/qbittorrent`, pinned): `network_mode:
  service:gluetun`, so it has **no network of its own**. It starts only after
  gluetun is healthy, publishes no ports itself, mounts storage **read-only**
  at `/data/storage`, and keeps its config in `QBT_CONFIG_HOST_PATH`
  (`./data/qbittorrent`).
- The qBittorrent **Web UI** is published on gluetun as
  `127.0.0.1:${QBT_WEBUI_PORT}:8081`, the host's loopback only. Reach it
  with an SSH tunnel:
  `ssh -L 8081:127.0.0.1:8081 you@server`, then open http://127.0.0.1:8081
  (user `admin`, password `QBT_PASSWORD` from `.env`).
- The **app container does not join** the VPN network and never reaches the
  internet through it.

### Port forwarding hand-off (gluetun → qBittorrent)

Per the current gluetun wiki (`setup/advanced/vpn-port-forwarding.md`),
gluetun runs `VPN_PORT_FORWARDING_UP_COMMAND` when a port is forwarded, with
`{{PORT}}` and `{{VPN_INTERFACE}}` filled in. docker-compose.yml uses the
wiki's qBittorrent command (adjusted to the Web UI port 8081) to set
qBittorrent's listening port **and** bind it to the VPN interface. The
`DOWN` command rebinds qBittorrent to `lo` (no connectivity) when forwarding
stops. These calls come from localhost inside the shared network namespace,
which is why the pre-seeded config enables qBittorrent's "bypass
authentication for clients on localhost". Every other client must log in.

Port-forwarding providers in gluetun: Private Internet Access, ProtonVPN,
Perfect Privacy and PrivateVPN. ProtonVPN with OpenVPN needs `+pmp` appended
to the username; with WireGuard, enable NAT-PMP when generating the key. The
gluetun wiki notes PIA port forwarding can be unreliable. **Providers change
their terms and features; check yours before relying on it.**

### Enabling or disabling the seeder after install

Both scripts work on a running install, never re-run install.sh, and never
restart the app, the database or Caddy. They share their setup code with
install.sh (`scripts/lib/seeder-setup.sh`), so all three behave the same.

```bash
scripts/enable-seeder.sh                            # turn it on
SEEDER_HEALTH_TIMEOUT=300 scripts/enable-seeder.sh  # slow VPN: wait longer (default 180 s)
scripts/disable-seeder.sh                           # turn it off
scripts/check-seeder-ip.sh                          # re-check at any time
```

**`scripts/enable-seeder.sh`**
1. Checks prerequisites (docker, compose plugin, openssl, an existing `.env`
   and `docker-compose.yml`). If the seeder is already enabled and both
   containers exist, it only offers to re-run the IP check.
2. Backs up `.env` to `.env.bak.<timestamp>` (mode 600).
3. Shows the same warning as install.sh option 3 and requires typing `yes`.
4. Asks for `VPN_SERVICE_PROVIDER` and the credentials (secrets typed
   hidden). Values already in `.env` are kept unless you say otherwise.
   Generates `QBT_PASSWORD` if there is none. Keeps `QBT_WEBUI_PORT` if it is
   free; otherwise it suggests the next free port and asks before changing it.
5. Pre-seeds qBittorrent's config exactly as install.sh does. An existing
   config is kept; only its Web UI password is reset if `QBT_PASSWORD` was
   just generated, so the login always matches `.env`.
6. Adds `seeder` to `COMPOSE_PROFILES` (deduplicated; `caddy` etc. kept).
7. Starts **only** gluetun, waits until it is healthy (VPN connected), then
   starts qBittorrent: `docker compose --profile seeder up -d --no-recreate <service>`.
8. Runs `scripts/check-seeder-ip.sh`. **Fails closed:** if gluetun does not
   become healthy in time, or the check does not print PASS (including when
   qBittorrent's IP equals the host's), it stops and removes both containers,
   takes `seeder` back out of `COMPOSE_PROFILES` and exits non-zero.
   qBittorrent is never left running without a passing check.
9. Confirms that app, mariadb and caddy were not restarted (container start
   times unchanged), then prints the Web UI location and SSH tunnel command.

**`scripts/disable-seeder.sh`**
1. Asks for confirmation and backs up `.env`.
2. Stops and removes the gluetun and qbittorrent containers (nothing else).
3. Removes `seeder` from `COMPOSE_PROFILES`, keeping the other profiles.
4. (a) Asks whether to delete qBittorrent's config directory
   (`QBT_CONFIG_HOST_PATH`). Default **no**: keeping it means torrents and
   settings are back as before when re-enabled.
5. (b) Asks whether to remove the VPN credentials and `QBT_PASSWORD` from
   `.env`. Default **yes**: they are not needed while the seeder is off.
6. Torrents in qBittorrent stop seeding. Approved Archive.org/GitHub mirror
   links on the site are unaffected. gluetun's small cache volume
   (`<project>_gluetun_data`) is kept; the script prints the command to remove it.

**Rolling back** a change to `.env`: every run printed its backup name, so
`cp .env.bak.<timestamp> .env`, then `docker compose up -d` to apply it.

**Mirror and torrent-link toggles** are in /admin/settings → External
sharing. `EXTERNAL_MIRRORS_ENABLED` in `.env` only seeds that setting: it is
read when the app starts and ignored once the setting has been saved in
/admin/settings. Neither script restarts the app, so they don't change it.

**Without the scripts** you would add the VPN variables to `.env`, append
`seeder` to `COMPOSE_PROFILES`, write qBittorrent's config yourself
(`scripts/lib/qbittorrent.sh`), run
`docker compose --profile seeder up -d gluetun qbittorrent` and then
`scripts/check-seeder-ip.sh`. That works, but the scripts also refuse to
leave an unchecked seeder running.

### Pre-seeded qBittorrent settings

Written once by `install.sh` (`scripts/lib/qbittorrent.sh`), never
overwritten. The key names were read back from the pinned qBittorrent
(5.2.4) after setting each preference through its API, not guessed:

| Setting | Key | Value |
|---|---|---|
| Bind to VPN interface | `[BitTorrent] Session\Interface` (+ `Session\InterfaceName`) | `tun0` |
| DHT / PeX / LSD | `Session\DHTEnabled`, `Session\PeXEnabled`, `Session\LSDEnabled` | `false` |
| Listening port | `Session\Port` | placeholder, set by gluetun's hook |
| UPnP / NAT-PMP | `[Network] PortForwardingEnabled` (4.4+), `[Preferences] Connection\UPnP` (older) | `false` |
| Save path | `Session\DefaultSavePath` | `/data/storage` (read-only) |
| Web UI | `WebUI\Address`, `WebUI\Port`, `WebUI\UseUPnP` | `*`, `8081`, `false` |
| Auth | `WebUI\Username`, `WebUI\Password_PBKDF2` | `admin`, PBKDF2-SHA512 (100k iterations) of `QBT_PASSWORD` |
| Localhost bypass | `WebUI\LocalHostAuth` | `false` (needed by gluetun's hook) |
| Host header check | `WebUI\HostHeaderValidation` | `false` (it compares the port, which breaks SSH-tunnelled access) |

**Version-dependent:** `Network\PortForwardingEnabled` replaced
`Connection\UPnP` in qBittorrent 4.4; `WebUI\Password_PBKDF2` exists since
4.2; `Session\Interface` lives under `[BitTorrent]` since the 4.4 settings
migration. If you change the pinned image, re-check these names.

### Seeding a file by hand (until src/seeder.rs is implemented)

Files are stored under a UUID key (`<storage>/<first 2 chars>/<key>`), not
their filename. The admin Files page shows each file's **storage key**.

1. Create a torrent for the file on your own machine, preferably
   **private-flagged and tracker-only** (e.g. `mktorrent -p -a <tracker-url>`).
2. Web UI → **Add torrent** → set **Save path** to
   `/data/storage/<first 2 chars of the key>`, start **stopped**.
3. Torrent → **Content** → rename the single file to the **storage key**.
4. **Force recheck**: it should reach 100% without downloading anything
   (storage is read-only, so it cannot write anyway). Then **Start**.

Only the VPN's IP is ever visible to peers.

### Privacy and safety

- **Container-level VPN, not host-wide.** Only qBittorrent's traffic uses
  the VPN; the site and the host keep their normal network.
- **Kill switch #1: gluetun's firewall.** On from container start, it blocks
  everything unless the VPN is up. If gluetun stops, qBittorrent's shared
  network namespace goes with it: no connectivity at all.
- **Kill switch #2: interface binding.** qBittorrent is bound to the VPN
  interface (`tun0`), and gluetun's down-hook rebinds it to `lo`.
- **Port forwarding requires a supporting provider** (see above); providers'
  terms change, so the admin must check theirs.
- **UPnP / NAT-PMP off**, so qBittorrent never opens ports on your router.
- **Web UI private:** loopback-only on the host, reached via SSH tunnel,
  password required.
- **Storage read-only** inside qBittorrent: it can only seed, never alter files.
- **DHT / PEX / LSD off** by default; prefer private-flagged, tracker-only
  torrents. Public mode exposes the seeder's (VPN) IP to anyone.
- **Web seeds are unaffected**: they are ordinary HTTP downloads from this site.
- **Cloudflare Tunnel does NOT hide BitTorrent traffic.** The tunnel only
  carries HTTP to this site. Peers connect to whatever machine seeds, which
  is why the seeder must only ever run inside the VPN container.
- **No-exposure alternatives:** link an Archive.org item torrent or GitHub
  Releases as mirrors (docs/MIRRORS.md). Then nobody on your side seeds at all.

### Verifying the setup (do this after any VPN or compose change)

1. `scripts/check-seeder-ip.sh`: must print **PASS** (qBittorrent's public
   IP differs from the host's). It FAILs loudly otherwise, including when
   the VPN is down (safe, but unconfirmed).
2. Web UI is loopback-only: `docker compose port gluetun 8081` shows
   `127.0.0.1:<port>`, and `ss -tlnp | grep <port>` shows only `127.0.0.1`.
3. Kill switch: `docker compose stop gluetun`, then
   `docker compose exec qbittorrent curl -m 10 https://api.ipify.org` must
   fail (qBittorrent has no network). `docker compose start gluetun` (and
   `docker compose restart qbittorrent`) afterwards.
4. Storage read-only: `docker compose exec qbittorrent touch /data/storage/x`
   must fail with "Read-only file system".

What was verified while building this (without a real VPN account): gluetun
accepts these settings, enables its firewall before connecting, and blocks
outbound traffic while the VPN is down. qBittorrent starts only after gluetun
is healthy. The pre-seeded password works and the Web UI requires login.
gluetun's exact up/down commands, run from the gluetun image inside
qBittorrent's namespace, set the port and interface. Storage is read-only.
**Not verified**: an actual VPN connection, real port forwarding, and a
PASS from `check-seeder-ip.sh`. These need a real provider account.
