#!/bin/bash
set -e # exit immediately if any command fails

# Backs up the database (mariadb-dump through the compose service) and the
# configuration (.env, Caddyfile, compose override files, qBittorrent's
# config if readable) -- NOT the file storage (back that up separately, see
# docs/BACKUP.md). Output files are mode 600. Restore: docs/BACKUP.md.
#
#   scripts/backup.sh
#   BACKUP_DIR=/srv/backups scripts/backup.sh
#   BACKUP_AGE_RECIPIENT=age1... scripts/backup.sh     # encrypt with age
#   BACKUP_GPG_RECIPIENT=you@example.org scripts/backup.sh  # or with gpg

cd "$(dirname "$0")/.."
# shellcheck source=scripts/lib/env.sh
source scripts/lib/env.sh
umask 077

if [ ! -f .env ]; then
        echo "No .env here -- nothing to back up."
        exit 1
fi

out_dir="${BACKUP_DIR:-./backups}"
mkdir -p "$out_dir"
out_abs="$(cd "$out_dir" && pwd)"

# Never inside the served storage, the incoming folder or the data tree.
for forbidden in "$(env_get STORAGE_HOST_PATH)" "$(env_get INCOMING_HOST_PATH)" ./data; do
        if [ -z "$forbidden" ] || [ ! -d "$forbidden" ]; then
                continue
        fi
        f_abs="$(cd "$forbidden" && pwd)"
        case "$out_abs/" in
        "$f_abs"/*)
                echo "Refusing to write backups inside ${forbidden} (${f_abs}). Set BACKUP_DIR elsewhere."
                exit 1
                ;;
        esac
done

ts="$(date +%Y%m%d-%H%M%S)"
db_file="${out_abs}/db-${ts}.sql"
cfg_file="${out_abs}/config-${ts}.tar.gz"

echo "Dumping the database..."
docker compose exec -T mariadb sh -c \
        'MYSQL_PWD="$MARIADB_ROOT_PASSWORD" mariadb-dump -uroot --single-transaction --routines --triggers "$MARIADB_DATABASE"' \
        > "$db_file"
if [ ! -s "$db_file" ]; then
        rm -f "$db_file"
        echo "The database dump is empty -- is the stack running (docker compose ps)?"
        exit 1
fi

echo "Archiving the configuration..."
cfg_items=(.env)
for f in Caddyfile docker-compose.override.yml docker-compose.db-publish.yml; do
        [ -f "$f" ] && cfg_items+=("$f")
done
qbt_dir="$(env_get QBT_CONFIG_HOST_PATH)"
if [ -n "$qbt_dir" ] && [ -r "${qbt_dir}/qBittorrent/qBittorrent.conf" ]; then
        cfg_items+=("$qbt_dir")
elif [ -n "$qbt_dir" ] && [ -d "$qbt_dir" ]; then
        echo "  (qBittorrent's config is owned by the container user; not included)"
fi
tar -czf "$cfg_file" "${cfg_items[@]}"
chmod 600 "$db_file" "$cfg_file"

encrypt() {
        local f="$1"
        if [ -n "${BACKUP_AGE_RECIPIENT:-}" ] && command -v age > /dev/null; then
                age -r "$BACKUP_AGE_RECIPIENT" -o "${f}.age" "$f" && rm -f "$f" && chmod 600 "${f}.age"
                echo "  ${f}.age"
        elif [ -n "${BACKUP_GPG_RECIPIENT:-}" ] && command -v gpg > /dev/null; then
                gpg --batch --yes --encrypt --recipient "$BACKUP_GPG_RECIPIENT" --output "${f}.gpg" "$f" && rm -f "$f" && chmod 600 "${f}.gpg"
                echo "  ${f}.gpg"
        else
                echo "  ${f}"
        fi
}

echo "Backup written:"
encrypt "$db_file"
encrypt "$cfg_file"
if [ -z "${BACKUP_AGE_RECIPIENT:-}${BACKUP_GPG_RECIPIENT:-}" ]; then
        echo ""
        echo "WARNING: not encrypted. The config archive contains .env (database passwords,"
        echo "TOTP key, VPN credentials). Keep it somewhere private, or set"
        echo "BACKUP_AGE_RECIPIENT / BACKUP_GPG_RECIPIENT (see docs/BACKUP.md)."
fi
echo ""
echo "File storage is not included: back up $(env_get STORAGE_HOST_PATH) separately (docs/BACKUP.md)."
