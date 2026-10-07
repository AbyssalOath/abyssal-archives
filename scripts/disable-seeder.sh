#!/bin/bash
set -e # exit immediately if any command fails

# Disables the VPN seeder: stops and removes the gluetun and qbittorrent
# containers and takes "seeder" out of COMPOSE_PROFILES. The app, the
# database and Caddy are not touched. See docs/TORRENTS.md.

cd "$(dirname "$0")/.."
# shellcheck source=scripts/lib/env.sh
source scripts/lib/env.sh
# shellcheck source=scripts/lib/qbittorrent.sh
source scripts/lib/qbittorrent.sh
# shellcheck source=scripts/lib/seeder-setup.sh
source scripts/lib/seeder-setup.sh

if ! command -v docker &> /dev/null || ! docker compose version &> /dev/null; then
        echo "Docker with the Compose plugin is required."
        exit 1
fi
if [ ! -f .env ] || [ ! -f docker-compose.yml ]; then
        echo "No .env / docker-compose.yml here -- nothing to disable."
        exit 1
fi

read -rp "Disable the VPN seeder (stop and remove the gluetun and qbittorrent containers)? [y/N]: " answer
case "$answer" in
[yY]*) ;;
*)
        echo "Nothing changed."
        exit 0
        ;;
esac

backup="$(env_backup)"
echo "Backed up .env to ${backup}."

echo "Stopping and removing the seeder containers (the site keeps running)..."
seeder_stop_and_remove

profiles="$(env_get COMPOSE_PROFILES)"
new_profiles="$(profiles_remove "$profiles" seeder)"
if [ "$new_profiles" != "$profiles" ]; then
        env_set COMPOSE_PROFILES "$new_profiles"
fi
echo "COMPOSE_PROFILES is now '$(env_get COMPOSE_PROFILES)'."

# (a) qBittorrent's config directory.
config_dir="$(seeder_config_dir)"
removed_config=0
if [ -d "$config_dir" ]; then
        echo ""
        echo "(a) Delete qBittorrent's config directory (${config_dir})?"
        echo "    It holds qBittorrent's settings, the torrents you added and its logs."
        echo "    Deleting it means the next scripts/enable-seeder.sh starts from a fresh"
        echo "    pre-seeded config. Keeping it lets you re-enable with everything as it was."
        read -rp "    Delete it? [y/N]: " answer
        case "$answer" in
        [yY]*)
                # Owned by the container user: clean it from a root container
                # and hand the empty directory back to this user.
                seeder_root_in_dir "$config_dir" \
                        "find /target -mindepth 1 -delete && chown $(id -u):$(id -g) /target"
                removed_config=1
                echo "    Deleted."
                ;;
        *) echo "    Kept." ;;
        esac
fi

# (b) VPN credentials and the Web UI password in .env.
echo ""
echo "(b) Remove the VPN credentials and QBT_PASSWORD from .env?"
echo "    They are not used while the seeder is off. You will type the VPN"
echo "    credentials again when re-enabling, and a new Web UI password is generated."
read -rp "    Remove them? [Y/n]: " answer
case "$answer" in
[nN]*) echo "    Kept." ;;
*)
        # shellcheck disable=SC2153 # defined in scripts/lib/seeder-setup.sh
        for key in $SEEDER_SECRET_KEYS; do
                env_unset "$key"
        done
        echo "    Removed: ${SEEDER_SECRET_KEYS// /, }."
        if [ "$removed_config" = "0" ] && [ -f "${config_dir}/qBittorrent/qBittorrent.conf" ]; then
                echo "    (The kept qBittorrent config still has the old Web UI password; re-enabling"
                echo "     resets it to the newly generated QBT_PASSWORD.)"
        fi
        ;;
esac

qbt_port="$(env_get QBT_WEBUI_PORT)"
echo ""
echo "The VPN seeder is off."
echo " - Torrents you added in qBittorrent have stopped seeding."
echo " - Approved Archive.org / GitHub mirror and torrent links on the site are"
echo "   unaffected (they are plain links; see /admin/settings -> External sharing)."
if [ -n "$qbt_port" ] && port_in_use "$qbt_port"; then
        echo " - NOTE: something still listens on 127.0.0.1:${qbt_port} (not the seeder containers)."
fi
echo " - gluetun's small server-list cache volume is kept; remove it with:"
echo "     docker volume rm $(env_get COMPOSE_PROJECT_NAME)_gluetun_data"
echo "To roll back the .env changes: cp ${backup} .env"
