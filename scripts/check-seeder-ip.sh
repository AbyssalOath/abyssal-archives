#!/bin/bash
set -e # exit immediately if any command fails

# Checks that the qBittorrent container (profile "seeder") reaches the
# internet ONLY through the VPN: compares the public IP seen from inside it
# with this host's public IP. Prints PASS only if both are known and differ.
# Uses no secrets. Re-run after ANY change to the VPN settings, .env or
# docker-compose.yml.
#
#   scripts/check-seeder-ip.sh
#   ECHO_IP_URL=https://ifconfig.me/ip scripts/check-seeder-ip.sh
#
# ECHO_IP_URL: any service answering with just the caller's IP
# (default https://api.ipify.org).

cd "$(dirname "$0")/.."
echo_ip_url="${ECHO_IP_URL:-https://api.ipify.org}"

fail() {
        echo ""
        echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
        echo "FAIL: $1"
        echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
        echo "Do not seed until this passes. See docs/TORRENTS.md (Privacy and safety)."
        exit 1
}

looks_like_ip() {
        [[ "$1" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || [[ "$1" =~ ^[0-9a-fA-F:]+:[0-9a-fA-F:]*$ ]]
}

if ! docker compose ps --status running --services 2>/dev/null | grep -qx qbittorrent; then
        fail "the qbittorrent container is not running (is the 'seeder' profile enabled and gluetun healthy?)"
fi

host_ip="$(curl -fsS --max-time 15 "$echo_ip_url" 2>/dev/null | tr -d '[:space:]' || true)"
if ! looks_like_ip "$host_ip"; then
        fail "could not determine this host's public IP via ${echo_ip_url}"
fi

seeder_ip="$(docker compose exec -T qbittorrent curl -fsS --max-time 15 "$echo_ip_url" 2>/dev/null | tr -d '[:space:]' || true)"
if ! looks_like_ip "$seeder_ip"; then
        fail "no internet access from inside qbittorrent (the VPN is down, or not connected yet). The kill switch is blocking traffic, which is safe, but the VPN path could not be confirmed."
fi

echo "Host public IP:        ${host_ip}"
echo "qBittorrent public IP: ${seeder_ip}"
if [ "$seeder_ip" = "$host_ip" ]; then
        fail "qBittorrent's traffic leaves through this host's own IP, NOT the VPN. Stop it now: docker compose stop qbittorrent"
fi
echo "PASS: qBittorrent's traffic leaves through the VPN (${seeder_ip}), not this host (${host_ip})."
echo "Re-run this after any change to the VPN settings, .env or docker-compose.yml."
