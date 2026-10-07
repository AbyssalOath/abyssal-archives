# Future direction

Ideas and plans beyond what exists today. Stubs mentioned here (toggles,
routes, traits) are already in the code but do nothing yet.

## Multi-user hosting

Member accounts exist (docs/MEMBERS.md). Possible next steps: more than one
administrator, transferring a project to another member, per-member limits
on the number of projects, and (only if wanted; it conflicts with the "nothing
leaves the server" rule) optional e-mail notifications.

## Storage

`StorageBackend` (see docs/STORAGE.md) with `local` implemented and `smb`
stubbed. Natural next backends: native SMB, S3-compatible object storage
(serving downloads via pre-signed URLs or proxied ranges). `files.storage_backend`
lets old and new backends coexist during a migration.

## Mirrors: the bandwidth relief valve

Mirrors are the intended long-term relief valve for bandwidth: GitHub
Releases, Archive.org items and other servers carrying the same file. Today
they are admin-curated (`file_mirrors`, docs/MIRRORS.md): any number per
file, approval states, an opt-in hash Verify, and public display behind
`EXTERNAL_MIRRORS_ENABLED`. **Archive.org item torrents** (`<id>_archive.torrent`)
can already be linked as `torrent` mirrors, which gives visitors a torrent
with no seeding on our side. Possible next steps: periodic re-verification
(still opt-in), and ordering mirrors by health or region.

## Mirror discovery (stub: `MIRROR_DISCOVERY_ENABLED`)

Toggle exists, does nothing, makes no network calls. Plan: **only when
enabled**, look files up **by hash** against a short list of known public
hosts (e.g. Archive.org search by SHA-1/MD5 where the host exposes them, or
well-known distro mirror indexes). Found URLs are inserted with
`source='discovered'` and `status='pending'`, never shown publicly until an
admin approves them, and should be verified (hash) before approval.

## Federation (stub: `FEDERATION_ENABLED`)

Toggle exists, does nothing, has no routes, makes no network calls. Design:

- Instances **opt in** explicitly and list the peers they federate with.
- Peers exchange **signed lists of (sha256, mirror URL)** pairs, signed with
  each instance's own key, so a list can be attributed and verified.
- Everything received lands as `source='federated'`, `status='pending'`.
  **Nothing is trusted without hash verification** (download + SHA-256 match)
  and admin approval.
- **No file content and no credentials are ever shared**, only hashes and
  public URLs. Users and accounts are never exposed either.

## Stored credentials (if upload automation is ever added)

Today the app stores **no** third-party credentials: uploads to Archive.org
or GitHub are done by the admin from their own machine (docs/MIRRORS.md). If
automation is added later:

- Use a **dedicated Archive.org account** and a **repository-scoped,
  fine-grained GitHub token** with only the permissions needed for releases.
- Encrypt them at rest with **AES-256-GCM**, using a key kept **separate from
  the database and from backups** (e.g. a mounted secret file), so a database
  or backup leak alone reveals nothing.
- **Write-only in the UI** (can be replaced, never displayed), decrypted only
  inside the upload job, never logged.
- Hashing (as for passwords) is not applicable: the keys must be usable
  again, so they have to be decryptable.

## Signed checksum files (GPG)

Signing works today without a key on the server: the admin signs
`SHA256SUMS` on their own machine and pastes the detached signature on the
release's Files page; it is served as `SHA256SUMS.asc` while it matches
(docs/VERIFYING.md). Possible next steps: `SHA512SUMS.asc`, and showing the
key fingerprint on the public pages.

## Torrents and seeding

See docs/TORRENTS.md: the planned "no-exposure torrent" (web seeds only: our
download URL plus approved http mirrors, no tracker/DHT/PEX), and the optional
VPN-contained qBittorrent seeder (`src/seeder.rs` is the integration stub).

## Separate download host

`DOWNLOAD_BASE_URL` already moves every download link to another hostname
served by the same app. A later step could serve downloads from a separate,
download-only deployment (same storage, no admin routes).
