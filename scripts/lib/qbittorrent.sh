# qBittorrent config pre-seeding for the "seeder" profile. Source from the
# repo root (needs openssl >= 3.0 for `openssl kdf`).
# shellcheck shell=bash
#
# Key names were read back from the qBittorrent this repo pins
# (linuxserver/qbittorrent 5.2.4) after setting each preference through its
# API, not guessed. Version-dependent keys are noted in docs/TORRENTS.md.

# Prints qBittorrent's WebUI\Password_PBKDF2 value for PASSWORD:
# PBKDF2-HMAC-SHA512, 100000 iterations, 16-byte random salt, 64-byte key,
# stored as "@ByteArray(<base64 salt>:<base64 key>)" (qBittorrent >= 4.2).
qbt_password_hash() {
        local password="$1" salt_hex salt_b64 key_b64
        salt_hex="$(openssl rand -hex 16)"
        # Hex -> raw bytes with printf (no xxd dependency).
        salt_b64="$(printf '%b' "$(printf '%s' "$salt_hex" | sed 's/../\\x&/g')" | base64 -w0)"
        key_b64="$(openssl kdf -keylen 64 -kdfopt digest:SHA512 -kdfopt pass:"$password" \
                -kdfopt hexsalt:"$salt_hex" -kdfopt iter:100000 -binary PBKDF2 | base64 -w0)" || return 1
        [ -n "$key_b64" ] || return 1
        printf '@ByteArray(%s:%s)' "$salt_b64" "$key_b64"
}

# Writes CONFIG_DIR/qBittorrent/qBittorrent.conf unless it already exists
# (never clobbers a config the admin may have changed in the Web UI).
# Returns 1 if a config was already there.
write_qbt_config() {
        local config_dir="$1" password="$2" conf hash
        conf="${config_dir}/qBittorrent/qBittorrent.conf"
        if [ -f "$conf" ]; then
                return 1
        fi
        if ! hash="$(qbt_password_hash "$password")"; then
                echo "ERROR: could not hash the qBittorrent password (needs 'openssl kdf', OpenSSL >= 3.0)." >&2
                exit 1
        fi
        mkdir -p "${config_dir}/qBittorrent"
        cat > "$conf" << EOF
# Pre-seeded by install.sh for the "seeder" profile. See docs/TORRENTS.md.
[BitTorrent]
# Bind to the VPN interface only: a second kill switch behind gluetun's
# firewall. gluetun's port-forwarding hook re-applies this with the real
# interface name and rebinds to "lo" when forwarding stops.
Session\\Interface=tun0
Session\\InterfaceName=tun0
# Placeholder; replaced by the VPN's forwarded port at runtime.
Session\\Port=6881
# Peer discovery off: DHT, peer exchange, local service discovery.
Session\\DHTEnabled=false
Session\\PeXEnabled=false
Session\\LSDEnabled=false
# Storage is mounted read-only here; torrents seed existing files only.
Session\\DefaultSavePath=/data/storage
Session\\TempPathEnabled=false

[Network]
# UPnP / NAT-PMP off (qBittorrent >= 4.4 key).
PortForwardingEnabled=false

[Preferences]
# UPnP off (older key, kept for safety).
Connection\\UPnP=false
# Web UI: listens inside the gluetun network namespace; docker publishes it
# only on the host's 127.0.0.1 (reach it through an SSH tunnel).
WebUI\\Address=*
WebUI\\Port=8081
WebUI\\UseUPnP=false
WebUI\\Username=admin
WebUI\\Password_PBKDF2="${hash}"
# Authentication is required for every client EXCEPT localhost inside the
# shared gluetun namespace, which gluetun's port-forwarding hook needs.
WebUI\\LocalHostAuth=false
# Host header validation compares ports too, which breaks access through a
# published or SSH-tunnelled port other than 8081. The Web UI is loopback-
# only on the host, so this check adds nothing here.
WebUI\\HostHeaderValidation=false
WebUI\\CSRFProtection=true

[LegalNotice]
Accepted=true
EOF
        chmod 600 "$conf"
}
