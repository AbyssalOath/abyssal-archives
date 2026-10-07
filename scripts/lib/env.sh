# Shared helpers for install.sh and scripts/*.sh. Source from the repo root.
# shellcheck shell=bash

# Prints VALUE quoted so docker compose (and dotenvy) read it back verbatim,
# including spaces, $, #, quotes and backslashes. Single quotes are fully
# literal; values containing a single quote use escaped double quotes.
env_quote() {
        local v="$1"
        if [[ "$v" != *"'"* ]]; then
                printf "'%s'" "$v"
        else
                v="${v//\\/\\\\}"
                v="${v//\"/\\\"}"
                v="${v//\$/\\\$}"
                printf '"%s"' "$v"
        fi
}

# True if KEY is present in .env.
env_has() {
        grep -q "^$1=" .env 2>/dev/null
}

# Prints KEY's value with surrounding quotes removed (good enough for the
# simple values this is used on: ports, URLs, secrets, paths).
env_get() {
        local v
        v="$(grep -E "^$1=" .env 2>/dev/null | tail -n 1 | cut -d '=' -f2-)"
        if [[ "$v" == \'*\' ]]; then
                v="${v:1:${#v}-2}"
        elif [[ "$v" == \"*\" ]]; then
                v="${v:1:${#v}-2}"
                v="${v//\\\$/\$}"
                v="${v//\\\"/\"}"
                v="${v//\\\\/\\}"
        fi
        printf '%s' "$v"
}

# Sets KEY to an already-quoted VALUE in .env, replacing any existing line(s)
# or appending. Keeps .env at mode 600.
env_set() {
        local key="$1" line="$1=$2" tmp
        tmp="$(mktemp .env.XXXXXX)"
        if env_has "$key"; then
                KEY="$key" LINE="$line" awk '
                        BEGIN { k = ENVIRON["KEY"] "=" }
                        index($0, k) == 1 { if (!done) { print ENVIRON["LINE"]; done = 1 } next }
                        { print }
                ' .env > "$tmp"
        else
                cat .env > "$tmp"
                printf '%s\n' "$line" >> "$tmp"
        fi
        chmod 600 "$tmp"
        mv "$tmp" .env
}

# Lowercase slug for docker project names: [a-z0-9-], at most 40 chars.
slugify() {
        local s
        s="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9]+/-/g; s/^-+//; s/-+$//' | cut -c1-40)"
        s="${s%-}"
        printf '%s' "${s:-filehost}"
}

# Validates a base URL (http/https, host, optional port, no path/query).
# Prints it without a trailing slash; returns 1 if invalid. Empty is valid.
normalize_base_url() {
        local u="${1%/}"
        if [ -z "$u" ]; then
                return 0
        fi
        if [[ "$u" =~ ^https?://[A-Za-z0-9.-]+(:[0-9]+)?$ ]] || [[ "$u" =~ ^https?://\[[0-9A-Fa-f:]+\](:[0-9]+)?$ ]]; then
                printf '%s' "$u"
        else
                return 1
        fi
}

# Removes the "admin settings override" marker for a settings key, so the
# .env value is used again on the next start. Needs the stack running.
reset_override() {
        local key="$1" user pw db
        user="$(env_get MARIADB_USER)"
        pw="$(env_get MARIADB_PASSWORD)"
        db="$(env_get MARIADB_DATABASE)"
        docker compose exec -T -e MYSQL_PWD="$pw" mariadb \
                mariadb -u"$user" "$db" -e "DELETE FROM site_settings WHERE \`key\` = 'override.${key}'"
}

# True if something listens on 127.0.0.1:PORT.
port_in_use() {
        (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null
}

# COMPOSE_PROFILES helpers: comma-separated lists, trimmed, empties dropped,
# duplicates removed, order kept.
profiles_normalize() {
        printf '%s' "$1" | tr ',' '\n' | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' \
                | awk 'NF && !seen[$0]++' | paste -sd, -
}

profiles_add() {
        profiles_normalize "$1,$2"
}

profiles_remove() {
        profiles_normalize "$1" | tr ',' '\n' | awk -v drop="$2" 'NF && $0 != drop' | paste -sd, -
}

profiles_has() {
        case ",$(profiles_normalize "$1")," in
        *",$2,"*) return 0 ;;
        *) return 1 ;;
        esac
}

# Removes KEY from .env (all occurrences). Keeps .env at mode 600.
env_unset() {
        local tmp
        env_has "$1" || return 0
        tmp="$(mktemp .env.XXXXXX)"
        KEY="$1" awk 'index($0, ENVIRON["KEY"] "=") != 1' .env > "$tmp"
        chmod 600 "$tmp"
        mv "$tmp" .env
}

# Copies .env to .env.bak.<timestamp> (mode 600) and prints the backup name.
env_backup() {
        local backup
        backup=".env.bak.$(date +%Y%m%d%H%M%S)"
        cp .env "$backup"
        chmod 600 "$backup"
        printf '%s' "$backup"
}
