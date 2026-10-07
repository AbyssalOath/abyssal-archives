# VPN seeder setup shared by install.sh (option 3), scripts/enable-seeder.sh
# and scripts/disable-seeder.sh, so the paths cannot drift apart.
# Source from the repo root after scripts/lib/env.sh and
# scripts/lib/qbittorrent.sh. See docs/TORRENTS.md.
# shellcheck shell=bash

# .env keys holding VPN credentials / seeder secrets (removed on disable).
# shellcheck disable=SC2034 # used by scripts/disable-seeder.sh
SEEDER_SECRET_KEYS="VPN_SERVICE_PROVIDER VPN_TYPE OPENVPN_USER OPENVPN_PASSWORD WIREGUARD_PRIVATE_KEY WIREGUARD_ADDRESSES SERVER_COUNTRIES QBT_PASSWORD"

seeder_warning() {
        echo ""
        echo "!!! WARNING -- read docs/TORRENTS.md first !!!"
        echo " - BitTorrent traffic is NOT hidden by Cloudflare Tunnel or your reverse proxy:"
        echo "   peers see the IP of whatever machine seeds."
        echo " - The seeder must ONLY ever run inside the VPN container this sets up"
        echo "   (gluetun, firewall kill switch). Never run a torrent client on this host."
        echo " - Your VPN provider must support port forwarding (gluetun: Private Internet"
        echo "   Access, ProtonVPN, Perfect Privacy, PrivateVPN). Providers change their"
        echo "   terms; check yours."
}

# Prints the warning and returns 0 only if the user types "yes".
seeder_confirm() {
        local answer
        seeder_warning
        read -rp "Type \"yes\" to set up the VPN seeder: " answer
        [ "$answer" = "yes" ]
}

# True if KEY is in .env with a non-empty value and the user wants to keep
# it. Secrets are never echoed. New installs never have these set, so for
# them this asks nothing.
seeder_keep_existing() {
        local key="$1" secret="$2" current answer
        current="$(env_get "$key")"
        [ -n "$current" ] || return 1
        if [ "$secret" = "1" ]; then
                read -rp "${key} is already set in .env (hidden). Keep it? [Y/n]: " answer
        else
                read -rp "${key} is already set to '${current}'. Keep it? [Y/n]: " answer
        fi
        case "$answer" in [nN]*) return 1 ;; *) return 0 ;; esac
}

# Prompts for the gluetun provider and credentials (secrets typed hidden)
# and stores them in .env, quoted so any character survives.
seeder_prompt_vpn() {
        local provider vpn_type wg_key wg_addr ovpn_user ovpn_pass countries
        echo ""
        if ! seeder_keep_existing VPN_SERVICE_PROVIDER 0; then
                provider=""
                while [ -z "$provider" ]; do
                        read -rp "VPN_SERVICE_PROVIDER (gluetun name, e.g. protonvpn, private internet access): " provider
                done
                env_set VPN_SERVICE_PROVIDER "$(env_quote "$provider")"
        fi
        if seeder_keep_existing VPN_TYPE 0; then
                vpn_type="$(env_get VPN_TYPE)"
        else
                read -rp "VPN type [openvpn/wireguard, default: openvpn]: " vpn_type
                vpn_type="${vpn_type:-openvpn}"
                env_set VPN_TYPE "$vpn_type"
        fi
        if [ "$vpn_type" = "wireguard" ]; then
                if ! seeder_keep_existing WIREGUARD_PRIVATE_KEY 1; then
                        read -rsp "WireGuard private key (input hidden): " wg_key
                        echo ""
                        env_set WIREGUARD_PRIVATE_KEY "$(env_quote "$wg_key")"
                fi
                if ! seeder_keep_existing WIREGUARD_ADDRESSES 0; then
                        read -rp "WireGuard addresses (blank if your provider doesn't need them): " wg_addr
                        env_set WIREGUARD_ADDRESSES "$(env_quote "$wg_addr")"
                fi
        else
                echo "(ProtonVPN: append +pmp to the OpenVPN username for port forwarding.)"
                if ! seeder_keep_existing OPENVPN_USER 0; then
                        read -rp "OpenVPN username: " ovpn_user
                        env_set OPENVPN_USER "$(env_quote "$ovpn_user")"
                fi
                if ! seeder_keep_existing OPENVPN_PASSWORD 1; then
                        read -rsp "OpenVPN password (input hidden): " ovpn_pass
                        echo ""
                        env_set OPENVPN_PASSWORD "$(env_quote "$ovpn_pass")"
                fi
        fi
        if ! seeder_keep_existing SERVER_COUNTRIES 0; then
                read -rp "Server countries (optional, comma-separated): " countries
                env_set SERVER_COUNTRIES "$(env_quote "$countries")"
        fi
}

# Generates QBT_PASSWORD unless .env already has one. Sets
# SEEDER_PASSWORD_NEW=1 when it generated one.
SEEDER_PASSWORD_NEW=0
seeder_ensure_password() {
        if [ -z "$(env_get QBT_PASSWORD)" ]; then
                env_set QBT_PASSWORD "$(openssl rand -hex 24)"
                SEEDER_PASSWORD_NEW=1
        fi
}

# First free port from 8081 that is not HTTP_PORT (needs port_in_use).
seeder_free_webui_port() {
        local http_port="$1" port=8081
        while port_in_use "$port" || [ "$port" = "$http_port" ]; do
                port=$((port + 1))
        done
        printf '%s' "$port"
}

# Chooses QBT_WEBUI_PORT. MODE "install": set it (fresh install, the value
# in .env is only the default). MODE "ask": keep the current value if it is
# free, otherwise ask before changing it.
seeder_choose_webui_port() {
        local mode="$1" http_port="$2" current suggested answer
        if [ "$mode" = "install" ]; then
                env_set QBT_WEBUI_PORT "$(seeder_free_webui_port "$http_port")"
                return
        fi
        current="$(env_get QBT_WEBUI_PORT)"
        if [ -n "$current" ] && ! port_in_use "$current" && [ "$current" != "$http_port" ]; then
                return
        fi
        suggested="$(seeder_free_webui_port "$http_port")"
        if [ -z "$current" ]; then
                env_set QBT_WEBUI_PORT "$suggested"
                return
        fi
        echo ""
        echo "QBT_WEBUI_PORT=${current} is already in use on this host (or is the site's port)."
        read -rp "Use ${suggested} instead? [Y/n]: " answer
        case "$answer" in
        [nN]*)
                echo "Keeping ${current}; the qBittorrent Web UI will fail to start until it is free."
                ;;
        *) env_set QBT_WEBUI_PORT "$suggested" ;;
        esac
}

# Runs SCRIPT with sh as root in a one-off container, with DIR mounted at
# /target (for files owned by the container users). Uses the MariaDB image,
# which every install has and which ships a shell (the app image is
# distroless). Extra arguments go to `docker compose run` (e.g. -e NAME=value).
seeder_root_in_dir() {
        local dir="$1" script="$2" output
        shift 2
        # -T and </dev/null: never read the caller's stdin (it holds the
        # answers to the script's remaining prompts). Output only on failure.
        if ! output="$(docker compose run -T --rm --no-deps --user 0 -v "$(cd "$dir" && pwd):/target" "$@" \
                --entrypoint sh mariadb -c "$script" < /dev/null 2>&1)"; then
                printf '%s\n' "$output" >&2
                return 1
        fi
}

seeder_config_dir() {
        local dir
        dir="$(env_get QBT_CONFIG_HOST_PATH)"
        printf '%s' "${dir:-./data/qbittorrent}"
}

# Pre-seeds qBittorrent's config (never overwrites an existing one). If a
# config is kept but QBT_PASSWORD was just generated, only its Web UI
# password hash is updated so the login matches .env.
seeder_write_config() {
        local dir conf hash
        dir="$(seeder_config_dir)"
        conf="${dir}/qBittorrent/qBittorrent.conf"
        if [ ! -e "$conf" ] && [ -d "$dir" ] && { [ ! -w "$dir" ] || { [ -d "${dir}/qBittorrent" ] && [ ! -w "${dir}/qBittorrent" ]; }; }; then
                # A directory left behind by qBittorrent (owned by the container
                # user, so not writable here): render the config in a temp dir
                # (gitignored name) and install it through a root container.
                local tmp
                tmp="$(mktemp -d -p "$PWD" .env.qbt.XXXXXX)"
                write_qbt_config "$tmp" "$(env_get QBT_PASSWORD)"
                seeder_root_in_dir "$dir" \
                        'mkdir -p /target/qBittorrent && cp /seed/qBittorrent/qBittorrent.conf /target/qBittorrent/ && chown -R 10001:10001 /target && chmod 600 /target/qBittorrent/qBittorrent.conf' \
                        -v "${tmp}:/seed:ro"
                rm -rf "$tmp"
                echo "qBittorrent config pre-seeded (VPN interface binding, DHT/PeX/LSD and UPnP off, Web UI auth)."
                return
        fi
        if write_qbt_config "$dir" "$(env_get QBT_PASSWORD)"; then
                echo "qBittorrent config pre-seeded (VPN interface binding, DHT/PeX/LSD and UPnP off, Web UI auth)."
                return
        fi
        if [ "$SEEDER_PASSWORD_NEW" = "1" ]; then
                hash="$(qbt_password_hash "$(env_get QBT_PASSWORD)")"
                # $QBT_HASH expands inside the container (passed with -e).
                # shellcheck disable=SC2016
                seeder_root_in_dir "$dir" \
                        'sed -i "s|^WebUI\\\\Password_PBKDF2=.*|WebUI\\\\Password_PBKDF2=\"$QBT_HASH\"|" /target/qBittorrent/qBittorrent.conf' \
                        -e "QBT_HASH=${hash}"
                echo "qBittorrent config already exists -- kept; only its Web UI password was reset to the new QBT_PASSWORD."
        else
                echo "qBittorrent config already exists -- left unchanged."
        fi
}

# Prints where the Web UI is and how to reach it.
seeder_print_webui() {
        local qbt_port
        qbt_port="$(env_get QBT_WEBUI_PORT)"
        echo "VPN seeder (qBittorrent behind gluetun):"
        echo "  Web UI: http://127.0.0.1:${qbt_port} on THIS host only. From your machine:"
        echo "    ssh -L ${qbt_port}:127.0.0.1:${qbt_port} $(id -un)@$(hostname -f 2>/dev/null || hostname)"
        echo "  then open http://127.0.0.1:${qbt_port} (user: admin, password: QBT_PASSWORD in .env)."
        echo "  Storage is mounted read-only in qBittorrent; DHT/PeX/LSD and UPnP are off."
}

# True once the qbittorrent container is running; waits up to ROUNDS x 4s.
seeder_wait_running() {
        local rounds="$1"
        for _ in $(seq 1 "$rounds"); do
                if docker compose ps --status running --services 2>/dev/null | grep -qx qbittorrent; then
                        return 0
                fi
                sleep 4
        done
        docker compose ps --status running --services 2>/dev/null | grep -qx qbittorrent
}

# True once gluetun reports healthy (VPN connected); waits up to SECONDS.
seeder_wait_gluetun_healthy() {
        local timeout="$1" waited=0 id status
        while [ "$waited" -lt "$timeout" ]; do
                id="$(docker compose ps -q gluetun 2>/dev/null)"
                status=""
                if [ -n "$id" ]; then
                        status="$(docker inspect -f '{{.State.Health.Status}}' "$id" 2>/dev/null || true)"
                fi
                if [ "$status" = "healthy" ]; then
                        return 0
                fi
                sleep 5
                waited=$((waited + 5))
        done
        return 1
}

# Start time of a compose service's container ("" if it has none).
seeder_started_at() {
        local id
        id="$(docker compose ps -q "$1" 2>/dev/null)"
        if [ -n "$id" ]; then
                docker inspect -f '{{.State.StartedAt}}' "$id" 2>/dev/null || true
        fi
}

# Stops and removes the seeder containers (qbittorrent first). Never
# touches other services. Removing them means the next start is created
# fresh from the current .env (no stale VPN settings).
seeder_stop_and_remove() {
        docker compose --profile seeder stop qbittorrent gluetun > /dev/null 2>&1 || true
        docker compose --profile seeder rm -f qbittorrent gluetun > /dev/null 2>&1 || true
}
