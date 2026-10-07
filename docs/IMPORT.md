# Importing large files

## Why not just upload?

Sites like this usually sit behind a reverse proxy or tunnel (NGINX Proxy
Manager, Cloudflare Tunnel). Cloudflare caps request bodies at about **100 MB**
and gives up on requests after about **100 seconds**; most proxies have similar
limits. A multi-GB ISO cannot be uploaded through a browser in that setup, and
even hashing one takes longer than the timeout.

So large files take a different path:

1. You copy the file to the server **out of band** (rsync, scp, SMB, a USB
   disk...) into the **incoming folder** (`INCOMING_HOST_PATH` on the host,
   `INCOMING_PATH` = `/data/incoming` inside the container).
2. In the admin area, open the release's **Files** page. The incoming folder
   is listed there, grouped by top-level folder, with **Import all**, **Import
   all in `<folder>`/** and a per-file **Import** button (or use the
   [command line](#from-the-command-line)).
3. Importing returns immediately. Files are processed **one at a time** in
   the background: each is hashed (SHA-256 and SHA-512 in one streamed pass,
   never loaded into memory), moved into storage under a random key and
   marked **ready**. Only ready files are listed publicly or downloadable.
   Imported files are stored **byte-for-byte**.

Browser upload (`ALLOW_WEB_UPLOAD`) remains available for small files up to
`MAX_UPLOAD_BYTES` (default 90,000,000 bytes, below Cloudflare's limit).

## Copying files in

Paths below use `/data/incoming` for the incoming folder on the server;
use your `INCOMING_HOST_PATH` (default `./data/incoming` inside the install
directory) if it differs.

```bash
# A whole folder into a subfolder (the trailing slash on the source copies
# its contents). The folder is kept: sources/a.tar.gz in the incoming folder
# becomes sources/a.tar.gz in the release.
rsync -avP --partial-dir=.rsync-partial sources-v0.1.0/ USER@SITEHOST:/data/incoming/sources/

# A single file (resumable). See the note on --partial below.
rsync -avP --partial-dir=.rsync-partial my-distro-2.0.iso USER@SITEHOST:/data/incoming/

# The plain form works too, with the caveat below:
rsync -avP --partial my-distro-2.0.iso USER@SITEHOST:/data/incoming/

# scp
scp my-distro-2.0.iso USER@SITEHOST:/data/incoming/
```

What the import list ignores, so half-copied files are not imported:

- hidden files and folders (names starting with `.`): rsync writes
  `.name.XXXXXX` temp files while transferring, and `--partial-dir=.rsync-partial`
  keeps interrupted transfers in a hidden folder
- names ending in `.part`, `.partial`, `.tmp` or `.crdownload`
- files modified in the last `IMPORT_MIN_AGE_SECS` seconds (default 30), shown
  as "still being copied"
- symlinks, and anything more than 3 folder levels deep (`a/b/c/file` is the
  deepest)

**Caveat with `--partial` (and `-P`):** if a transfer is interrupted, rsync
keeps the incomplete file under its **final name**. After 30 seconds it looks
like a finished file and would be offered for import. Prefer
`--partial-dir=.rsync-partial`, and re-run rsync until it completes before
importing. Compare the SHA-256 shown after import with `sha256sum` on your copy.

The submitted path is always relative to the incoming folder. The app
canonicalizes it, checks it is still inside the folder, is a regular file and
not a symlink, and rejects anything else (absolute paths, `..`, hidden or
partial files).

## Folders, duplicates and reruns

A file's **path in the release is its path relative to the incoming
folder**. With

```
incoming/
  abyssal-sanctum-v0.1.0.iso
  abyssal-sanctum-v0.1.0-secureboot.iso
  ...
  sources/
    SHA256SUMS
    SOURCE-NOTES.txt
    a.tar.gz
    ...
```

**Import all** gives the release the same tree, and every file keeps its
path everywhere: in the file list, in its download URL
(`/p/<project>/<version>/sources/a.tar.gz`) and in the release's generated
`SHA256SUMS` (`<hash>  sources/a.tar.gz`), so `sha256sum -c` works from the
root of a downloaded release. **Import all in sources/** imports only that
folder (paths still start with `sources/`).

- **Generated names are reserved at the top level.** Every release serves
  its own `SHA256SUMS`, `SHA512SUMS`, `SHA256SUMS.asc` and `files.json`, so
  a file with one of those names can only be imported inside a folder.
  `sources/SHA256SUMS` is fine and does not clash.
- **Files are never overwritten.** Paths are compared in full: importing
  `sources/a.tar.gz` twice is refused with a clear message, while
  `extra/a.tar.gz` next to `sources/a.tar.gz` is fine. To replace a file,
  delete it from the release first.
- **Reruns are safe.** If the release already has a ready file at that path
  **with the same size**, the incoming file is hashed: the same SHA-256
  counts as **skipped** (and the duplicate is removed from the incoming
  folder, as an import would have); anything else is refused. An earlier
  *failed* attempt at the same path is simply replaced.
- File and folder names are made safe (letters, digits and `._-+()[]~ ,@=`;
  other characters become `_`).

### Progress and results

Every import (one file, a folder or everything) is a **batch**. The
release's Files page shows the latest batches; each has a page
(`/admin/imports/<id>`) with progress, a result per file (imported, skipped,
failed with the reason) and failures listed first. It refreshes itself
while the batch runs; you can leave it, the import keeps going. After an app
restart, unfinished batches are marked "interrupted by restart": run the
import again (finished files are skipped).

### Free space

A batch is **refused up front**, before anything is copied, when its new
files would leave less than `STORAGE_MIN_FREE_BYTES` (default 1G) free in
storage. Each file is checked again right before it is copied. With the
default two separate mounts (see [Rename vs. copy](#rename-vs-copy)) a file
briefly exists twice while it is copied, so keep about twice the release
size free while importing, or use the single mount below.

### From the command line

The same import, for scripts. It runs in the foreground, one file at a time,
prints a line per file and a summary, and records a batch like the web UI:

```bash
docker compose exec app /app/filehost import --release <project>/<version> [<folder>]

# e.g. everything in the incoming folder, then only sources/
docker compose exec app /app/filehost import --release abyssal-sanctum/v0.1.0
docker compose exec app /app/filehost import --release abyssal-sanctum/v0.1.0 sources
```

`<folder>` is relative to the incoming folder (`/data/incoming/sources`
works too). The release must exist (create it in the admin first). Exit
status: `0` everything imported or skipped, `1` some files failed or were
refused, `2` nothing was done (bad arguments, unknown release, nothing to
import, not enough free space).

Do not restart the app while a command-line import runs: the app marks
unfinished imports as interrupted when it starts. Just run it again.

## Permissions

The app runs as UID/GID **10001** inside the container (fixed in the
Dockerfile). Both the container and you need to write to the incoming folder
(you copy files in, the import moves them out), so install.sh sets:

```bash
sudo chown -R 10001:10001 data/storage            # only the app writes here
sudo chown "$(id -u)":10001 data/incoming          # you own it, the app's group can write
sudo chmod 2775 data/incoming                      # group-writable; setgid keeps group 10001 on new files
```

Files you copy in must be **readable** by the container (mode 644 is fine).
If your source files are 600, add `--chmod=F644,D2775` to rsync. If you copy
in as a different user, give that user write access to the folder (e.g. add
it to a group with GID 10001: `sudo groupadd -g 10001 filehost-data && sudo usermod -aG filehost-data <user>`).

For SMB drops, configure the share so new files are created group-readable
and the directory stays writable by GID 10001.

## Rename vs. copy

Moving a file into storage is instant (`rename`) when the incoming folder and
the storage folder are on the **same filesystem and the same mount**.
Otherwise the import copies the file, verifies the size, and deletes the
original. The copy needs temporary free space equal to the file size.

The default `docker-compose.yml` uses **two separate bind mounts**, and Linux
never renames across mount points, even when both are on the same disk. So
by default imports copy. To get instant imports, keep both folders under one
host directory on one filesystem and mount that directory once, with a
`docker-compose.override.yml` (ignored by git) next to `docker-compose.yml`:

```yaml
services:
  app:
    volumes: !override
      - ./data:/data        # contains storage/ and incoming/
```

(With `STORAGE_PATH=/data/storage` and `INCOMING_PATH=/data/incoming`, the
defaults.) Then `docker compose up -d`.

## Failures and restarts

If an import fails, the row shows **failed** with a short reason. Delete it
and import again. If the failure happened before the move, the file is still
in the incoming folder. Imports interrupted by an app restart are marked
failed with "interrupted by restart" at the next start.
