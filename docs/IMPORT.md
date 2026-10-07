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
2. In the admin area, open the release's **Files** page. Every file in the
   incoming folder is listed with an **Import** button.
3. Clicking Import returns immediately. A background task hashes the file
   (SHA-256 and SHA-512 in one streamed pass), moves it into storage under a random key and marks it
   **ready**. The page refreshes itself every 5 seconds while that runs. Only
   ready files are listed publicly or downloadable.

Browser upload (`ALLOW_WEB_UPLOAD`) remains available for small files up to
`MAX_UPLOAD_BYTES` (default 90,000,000 bytes, below Cloudflare's limit).

## Copying files in

```bash
# rsync (resumable). See the note on --partial below.
rsync -avP --partial-dir=.rsync-partial my-distro-2.0.iso user@server:/path/to/incoming/

# The plain form works too, with the caveat below:
rsync -avP --partial my-distro-2.0.iso user@server:/path/to/incoming/

# scp
scp my-distro-2.0.iso user@server:/path/to/incoming/
```

What the import list ignores, so half-copied files are not imported:

- hidden files and folders (names starting with `.`): rsync writes
  `.name.XXXXXX` temp files while transferring, and `--partial-dir=.rsync-partial`
  keeps interrupted transfers in a hidden folder
- names ending in `.part`, `.partial`, `.tmp` or `.crdownload`
- files modified in the last `IMPORT_MIN_AGE_SECS` seconds (default 30), shown
  as "still being copied"
- symlinks, and anything more than 3 directory levels deep

**Caveat with `--partial` (and `-P`):** if a transfer is interrupted, rsync
keeps the incomplete file under its **final name**. After 30 seconds it looks
like a finished file and would be offered for import. Prefer
`--partial-dir=.rsync-partial`, and re-run rsync until it completes before
importing. Compare the SHA-256 shown after import with `sha256sum` on your copy.

The submitted path is always relative to the incoming folder. The app
canonicalizes it, checks it is still inside the folder, is a regular file and
not a symlink, and rejects anything else (absolute paths, `..`, hidden or
partial files).

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
