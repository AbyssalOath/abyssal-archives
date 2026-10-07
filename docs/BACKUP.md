# Backups and recovery

A complete backup has three parts:

1. **Database** (projects, releases, file records, settings, the admin
   account): `scripts/backup.sh`.
2. **Configuration** (`.env` with all secrets incl. `TOTP_ENCRYPTION_KEY`,
   `Caddyfile`, compose override files): also `scripts/backup.sh`.
3. **File storage** (`STORAGE_HOST_PATH`, the actual ISOs): large, so backed
   up separately with your usual tools.

## scripts/backup.sh

```bash
scripts/backup.sh                                   # -> ./backups/
BACKUP_DIR=/srv/backups/site scripts/backup.sh      # elsewhere
BACKUP_AGE_RECIPIENT=age1... scripts/backup.sh      # encrypt with age
BACKUP_GPG_RECIPIENT=ops@example.org scripts/backup.sh  # or with gpg
```

- `db-<time>.sql`: `mariadb-dump --single-transaction` through the compose
  service (needs the stack running).
- `config-<time>.tar.gz`: `.env`, `Caddyfile`, compose overrides (and
  qBittorrent's config if readable).
- Files are created owner-only (umask 077, mode 600). The script refuses to
  write into the storage or incoming folders or `./data`, so backups are
  never downloadable through the site. `./backups/` is git-ignored.
- **Encrypt** whenever the backup leaves this machine: the config archive
  holds every secret. With neither recipient set, the script says so loudly.

Copy backups off the server (another machine, object storage). A backup on
the same disk does not survive a disk failure.

## File storage

```bash
# example: incremental copy to another machine
sudo rsync -a --delete ./data/storage/ backup-host:/backups/<site>/storage/
```

Files keep their UUID names; the database maps them to releases, so restore
storage and database from about the same point in time. After a restore,
**Verify storage integrity** on the admin dashboard re-hashes everything.

## Restore

```bash
# 1. code and configuration
git clone <repo-url> <repo-name> && cd <repo-name>
tar -xzf config-<time>.tar.gz              # (decrypt first: age -d / gpg -d)
chmod 600 .env

# 2. file storage back into STORAGE_HOST_PATH, owned by the container user
sudo rsync -a backup-host:/backups/<site>/storage/ ./data/storage/
sudo chown -R 10001:10001 ./data/storage

# 3. start the database only, load the dump, then everything
docker compose up -d mariadb
docker compose exec -T mariadb sh -c \
  'MYSQL_PWD="$MARIADB_ROOT_PASSWORD" mariadb -uroot "$MARIADB_DATABASE"' < db-<time>.sql
./install.sh                                # asks nothing; rebuilds and starts
```

Then sign in, and run **Verify storage integrity** from the dashboard.

Lost `TOTP_ENCRYPTION_KEY` (or 2FA device and recovery codes)? On the server:
`docker compose exec app /app/filehost admin reset-2fa`, then sign in with
the password and set up 2FA again.
