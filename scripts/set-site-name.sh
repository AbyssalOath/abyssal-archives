#!/bin/bash
set -e # exit immediately if any command fails

# Changes SITE_NAME in .env.
#
#   scripts/set-site-name.sh "New Site Name" [--reset-override]
#
# The site name in /admin/settings overrides .env once it has been saved
# there with a different value. --reset-override removes that override (the
# containers must be running) so the .env value applies again.

cd "$(dirname "$0")/.."
# shellcheck source=scripts/lib/env.sh
source scripts/lib/env.sh

if [ ! -f .env ]; then
        echo "No .env found -- run ./install.sh first."
        exit 1
fi

new_name=""
reset=0
for arg in "$@"; do
        case "$arg" in
        --reset-override) reset=1 ;;
        *) new_name="$arg" ;;
        esac
done

while [ -z "$new_name" ]; do
        read -rp "New site name: " new_name
done
if [ "${#new_name}" -gt 100 ]; then
        echo "Site name must be at most 100 characters."
        exit 1
fi

env_set SITE_NAME "$(env_quote "$new_name")"
echo "SITE_NAME updated in .env."

if [ "$reset" = "1" ]; then
        reset_override site_name
        echo "Admin settings override cleared; the .env value applies from the next start."
fi

echo ""
echo "Apply it by recreating the app container (a plain restart keeps the old environment):"
echo "  docker compose up -d app"
echo ""
echo "Note: if the site name was changed in /admin/settings, that value wins over .env."
echo "Either change it there, or re-run this script with --reset-override."
