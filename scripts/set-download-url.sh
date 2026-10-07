#!/bin/bash
set -e # exit immediately if any command fails

# Changes DOWNLOAD_BASE_URL in .env (e.g. https://dl.example.com). An empty
# value serves downloads from the same address as the site.
#
#   scripts/set-download-url.sh "https://dl.example.com" [--reset-override]
#   scripts/set-download-url.sh "" [--reset-override]
#
# A value saved in /admin/settings overrides .env; --reset-override removes
# that override (the containers must be running).

cd "$(dirname "$0")/.."
# shellcheck source=scripts/lib/env.sh
source scripts/lib/env.sh

if [ ! -f .env ]; then
        echo "No .env found -- run ./install.sh first."
        exit 1
fi

new_url=""
have_arg=0
reset=0
for arg in "$@"; do
        case "$arg" in
        --reset-override) reset=1 ;;
        *)
                new_url="$arg"
                have_arg=1
                ;;
        esac
done

if [ "$have_arg" = "0" ]; then
        read -rp "Download base URL (e.g. https://dl.example.com, blank = same as the site): " new_url
fi
if ! new_url="$(normalize_base_url "$new_url")"; then
        echo "Invalid URL: use http:// or https:// with a host name and optional port, no path."
        exit 1
fi

env_set DOWNLOAD_BASE_URL "$new_url"
echo "DOWNLOAD_BASE_URL set to '${new_url:-<same host as the site>}' in .env."

if [ "$reset" = "1" ]; then
        reset_override download_base_url
        echo "Admin settings override cleared; the .env value applies from the next start."
fi

echo ""
echo "Apply it by recreating the app container:"
echo "  docker compose up -d app"
echo ""
echo "Note: a download base URL saved in /admin/settings wins over .env."
echo "Either change it there, or re-run this script with --reset-override."
