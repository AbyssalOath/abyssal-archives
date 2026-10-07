#!/bin/bash
set -e # exit immediately if any command fails

# Enables the VPN seeder (compose profile "seeder": gluetun + qBittorrent) on
# an already-installed site, without re-running install.sh and without
# restarting the app, the database or Caddy. Fails CLOSED: unless
# scripts/check-seeder-ip.sh passes, the seeder is stopped again and removed
# from COMPOSE_PROFILES. See docs/TORRENTS.md.
#
#   scripts/enable-seeder.sh
#   SEEDER_HEALTH_TIMEOUT=300 scripts/enable-seeder.sh   # slow VPN (seconds, default 180)

cd "$(dirname "$0")/.."
# shellcheck source=scripts/lib/env.sh
source scripts/lib/env.sh
# shellcheck source=scripts/lib/qbittorrent.sh
source scripts/lib/qbittorrent.sh
# shellcheck source=scripts/lib/seeder-setup.sh
source scripts/lib/seeder-setup.sh

health_timeout="${SEEDER_HEALTH_TIMEOUT:-180}"

# --- Check prerequisites ---
for cmd in docker openssl; do
        if ! command -v "$cmd" &> /dev/null; then
                echo "$cmd is required. Install it before continuing."
                exit 1
        fi
done
if ! docker compose version &> /dev/null; then
        echo "Docker Compose plugin is not available. Install it before continuing."
        exit 1
fi
if [ ! -f .env ] || [ ! -f docker-compose.yml ]; then
        echo "No .env / docker-compose.yml here -- install the site first (./install.sh)."
        exit 1
fi

profiles="$(env_get COMPOSE_PROFILES)"
seeder_containers="$(docker compose --profile seeder ps -a --format '{{.Service}}' 2>/dev/null | grep -cxE 'gluetun|qbittorrent' || true)"
if profiles_has "$profiles" seeder && [ "$seeder_containers" = "2" ]; then
        echo "The VPN seeder is already enabled (COMPOSE_PROFILES has 'seeder', both containers exist)."
        read -rp "Re-run the IP check now? [Y/n]: " answer
        case "$answer" in
        [nN]*) exit 0 ;;
        *) exec scripts/check-seeder-ip.sh ;;
        esac
fi

# --- Back up .env before touching it ---
backup="$(env_backup)"
echo "Backed up .env to ${backup}."

if ! seeder_confirm; then
        rm -f "$backup"
        echo "Not confirmed -- nothing changed."
        exit 1
fi

# --- VPN settings and qBittorrent config (shared with install.sh) ---
http_port="$(env_get HTTP_PORT)"
seeder_prompt_vpn
seeder_ensure_password
for kv in QBT_USERNAME=admin QBT_CONFIG_HOST_PATH=./data/qbittorrent; do
        if ! env_has "${kv%%=*}"; then
                env_set "${kv%%=*}" "${kv#*=}"
        fi
done
seeder_choose_webui_port ask "$http_port"
seeder_write_config

new_profiles="$(profiles_add "$profiles" seeder)"
if [ "$new_profiles" != "$profiles" ]; then
        env_set COMPOSE_PROFILES "$new_profiles"
        echo "COMPOSE_PROFILES set to '${new_profiles}'."
fi

# Fail closed: stop the seeder, take it out of COMPOSE_PROFILES so a later
# 'docker compose up -d' does not start it unchecked, and explain.
fail_closed() {
        echo ""
        echo "!!! $1"
        echo "Stopping and removing qbittorrent and gluetun: the seeder never runs without a"
        echo "passing IP check."
        seeder_stop_and_remove
        env_set COMPOSE_PROFILES "$(profiles_remove "$(env_get COMPOSE_PROFILES)" seeder)"
        echo "Removed 'seeder' from COMPOSE_PROFILES (now '$(env_get COMPOSE_PROFILES)')."
        echo "The VPN settings stay in .env: fix them (see 'docker compose logs gluetun')"
        echo "and run scripts/enable-seeder.sh again. Previous .env: ${backup}"
        exit 1
}

# --- Start ONLY the seeder services ---
# Record when the other services started, to prove they were not touched.
declare -A started_before
for svc in app mariadb caddy; do
        started_before[$svc]="$(seeder_started_at "$svc")"
done

# Leftovers from an earlier failed or manual attempt would keep stale VPN
# settings (--no-recreate below never recreates): start from scratch.
if [ "$seeder_containers" != "0" ]; then
        echo "Removing leftover seeder containers from an earlier attempt..."
        seeder_stop_and_remove
fi

echo ""
echo "Starting gluetun (VPN)..."
docker compose --profile seeder up -d --no-recreate gluetun || fail_closed "gluetun could not be started."
echo "Waiting up to ${health_timeout}s for the VPN to connect..."
if ! seeder_wait_gluetun_healthy "$health_timeout"; then
        fail_closed "gluetun did not become healthy within ${health_timeout}s (VPN not connected). Check: docker compose logs gluetun"
fi
echo "VPN connected. Starting qBittorrent..."
docker compose --profile seeder up -d --no-recreate qbittorrent || fail_closed "qbittorrent could not be started."
seeder_wait_running 15 || fail_closed "qbittorrent did not start."
sleep 5
if ! timeout 120 scripts/check-seeder-ip.sh; then
        fail_closed "The IP check did not PASS (or timed out)."
fi

# --- The site must not have been restarted ---
for svc in app mariadb caddy; do
        after="$(seeder_started_at "$svc")"
        if [ -n "${started_before[$svc]}" ] && [ "$after" != "${started_before[$svc]}" ]; then
                echo "WARNING: ${svc} was restarted (started ${started_before[$svc]}, now ${after})."
        elif [ -n "$after" ]; then
                echo "${svc}: untouched (running since ${after})."
        fi
done

echo ""
seeder_print_webui
echo ""
echo "Mirror/torrent link toggles are in /admin/settings -> External sharing."
echo "(EXTERNAL_MIRRORS_ENABLED in .env only seeds that setting; it is read when the"
echo "app starts and is ignored once the setting has been saved in /admin/settings.)"
echo "Re-run scripts/check-seeder-ip.sh after ANY change to the VPN settings, .env"
echo "or docker-compose.yml. To turn the seeder off: scripts/disable-seeder.sh"
