#!/bin/sh
# The container's entry point. Runs hxd with a mounted config file when
# there is one, and otherwise with one written from HXD_* environment
# variables at every start, so changing a variable and recreating the
# container is the whole of reconfiguring it. docs/docker.md lists the
# variables.
#
#   hxd-entrypoint                          serve
#   hxd-entrypoint registrar invites --add 5
#   hxd-entrypoint news-reindex             any hxd subcommand, same config
#   hxd-entrypoint hlid inspect card.cbor   anything else runs as given
#
# No pathname expansion anywhere: lists are split on commas unquoted, and
# an IPv6 address in brackets is a glob pattern.
set -euf

DATA=/var/lib/hxd-ng
HXD_CONFIG=${HXD_CONFIG:-/etc/hxd-ng/hxd-ng.toml}
GENERATED=/run/hxd-ng/hxd-ng.toml

case ${1:-} in
    "" | -* | inbox | news-reindex | push | identity | registrar) ;;
    *) exec "$@" ;;
esac

die() {
    echo "hxd-entrypoint: $*" >&2
    exit 1
}

# These print rather than return, and are never called inside $(...):
# a die there would end only the subshell, and the bad value would be
# written anyway.

# A TOML basic string. A newline would end the line it sits on, so it is
# refused rather than escaped: no variable here has a use for one.
q() {
    case $1 in
        *'
'*) die "a value may not contain a newline" ;;
    esac
    printf '"%s"' "$(printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g')"
}

# `key = "value"`.
kv() {
    printf '%s = ' "$1"
    q "$2"
    echo
}

# `key = [...]` from a comma-separated list; blanks are dropped.
kvlist() {
    printf '%s = [' "$1"
    sep=
    old_ifs=$IFS
    IFS=,
    for item in $2; do
        item=$(printf '%s' "$item" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')
        [ -n "$item" ] || continue
        printf '%s' "$sep"
        q "$item"
        sep=", "
    done
    IFS=$old_ifs
    echo "]"
}

# on/off for a variable, with its default.
on() {
    eval "v=\${$1:-$2}"
    case $v in
        1 | true | yes | on) return 0 ;;
        0 | false | no | off) return 1 ;;
        *) die "$1 must be on or off, got \"$v\"" ;;
    esac
}

# A whole number from a variable, or nothing when it is unset.
num() {
    eval "v=\${$1:-}"
    case $v in
        "") return 0 ;;
        *[!0-9]*) die "$1 must be a whole number, got \"$v\"" ;;
    esac
    printf '%s = %s\n' "$2" "$v"
}

# A string from a variable, or nothing when it is unset.
str() {
    eval "v=\${$1:-}"
    [ -z "$v" ] || kv "$2" "$v"
}

# A warning for a variable whose feature is off, so it does nothing.
unused() {
    var=$1
    shift
    eval "v=\${$var:-}"
    [ -z "$v" ] || echo "hxd-entrypoint: $var ignored: $*" >&2
}

# The container's default gateway: the address a proxy on the host is
# seen from when it reaches the ng port through a published port.
gateway() {
    hex=$(awk '$2 == "00000000" { print $3; exit }' /proc/net/route 2>/dev/null)
    [ ${#hex} -eq 8 ] || return 0
    # /proc/net/route prints the address in host byte order: little-endian.
    printf '%d.%d.%d.%d' "0x${hex#??????}" "0x$(echo "$hex" | cut -c5-6)" \
        "0x$(echo "$hex" | cut -c3-4)" "0x$(echo "$hex" | cut -c1-2)"
}

# The addresses the ng port should believe X-Forwarded-For and
# X-Hotline-Client-Cert from, with `gateway` standing for the container's
# default gateway. Never by default: the gateway is where the host's
# docker-proxy connects from on behalf of every client of a port
# published on all addresses, and on the host network it is the router.
trusted_proxies() {
    out=
    old_ifs=$IFS
    IFS=,
    for item in $1; do
        item=$(printf '%s' "$item" | tr -d '[:space:]')
        case $item in
            "" | none) continue ;;
            gateway)
                item=$(gateway)
                if [ -z "$item" ]; then
                    echo "hxd-entrypoint: HXD_NG_TRUSTED_PROXIES: no default gateway to trust" >&2
                    continue
                fi
                echo "hxd-entrypoint: trusting the gateway, $item, as a proxy" >&2
                ;;
        esac
        out="${out:+$out,}$item"
    done
    IFS=$old_ifs
    kvlist trusted_proxies "$out"
}

# `key = [...]` of fingerprints from a variable, checked here so a typo is
# named after the variable rather than the generated file. hxd checks the
# rest, the padding bits included, and refuses to start on a bad one.
fingerprints() {
    eval "v=\${$1:-}"
    old_ifs=$IFS
    IFS=,
    for fp in $v; do
        fp=$(printf '%s' "$fp" | tr -d '[:space:]')
        case $fp in
            "") ;;
            *[!0-9A-TV-Za-tv-z]*) die "$1: $fp is not a fingerprint: give the 52-character form hlid prints" ;;
            *) [ ${#fp} -eq 52 ] || die "$1: $fp is not a fingerprint: give the 52-character form hlid prints" ;;
        esac
    done
    IFS=$old_ifs
    kvlist "$2" "$v"
}

generate() {
    ng=false
    on HXD_NG on && ng=true

    echo "# Written by hxd-entrypoint from HXD_* variables at container start."
    echo "# Edits are lost at the next start: mount a file at $HXD_CONFIG instead."
    echo
    echo "[server]"
    echo 'bind = "0.0.0.0:5500"'
    str HXD_NAME name
    num HXD_BAN_TIME ban_time
    num HXD_LOGIN_TIMEOUT login_timeout
    echo
    echo "[paths]"
    echo "accounts = \"$DATA/accounts\""
    agreement=${HXD_AGREEMENT_FILE:-}
    if [ -z "$agreement" ] && [ -f "$DATA/agreement.txt" ]; then
        agreement=$DATA/agreement.txt
    fi
    [ -z "$agreement" ] || kv agreement "$agreement"

    if $ng; then
        echo
        echo "[ng]"
        kv bind "${HXD_NG_BIND:-0.0.0.0:5700}"
        num HXD_NG_GRACE grace
        num HXD_NG_MAX_DETACHED_PER_ADDR max_detached_per_addr
        trusted_proxies "${HXD_NG_TRUSTED_PROXIES-127.0.0.1,::1}"
        str HXD_NG_FORWARDED_HEADER forwarded_header
    fi

    # On with the ng port it lives on; asked for without it, an error.
    if on HXD_IDENTITY "$ng"; then
        $ng || die "HXD_IDENTITY needs HXD_NG: the identity endpoints are on the ng port"
        echo
        echo "[identity]"
        echo "key = \"$DATA/identity-server.key\""
        echo "successors = \"$DATA/identity-successors\""
        str HXD_IDENTITY_NEW_ACCOUNTS new_accounts
        str HXD_IDENTITY_UNATTESTED unattested
        str HXD_IDENTITY_WEB web
        # The generated file is rewritten at every start, so these are the
        # only lists that last; `hxd identity revoke` is refused below.
        fingerprints HXD_REVOKED_IDENTITIES revoked_identities
        fingerprints HXD_REVOKED_DEVICES revoked_devices
    else
        unused HXD_REVOKED_IDENTITIES "HXD_IDENTITY is off"
        unused HXD_REVOKED_DEVICES "HXD_IDENTITY is off"
    fi

    # One SQLite file holds everything. The first section that is on names
    # it; the later ones default to it and share its connection.
    db="\"$DATA/hxd-ng.sqlite\""
    if on HXD_INBOX on; then
        echo
        echo "[inbox]"
        echo "db = $db"
        num HXD_INBOX_MAX_QUEUED max_queued
        num HXD_INBOX_RETAIN_UNREAD retain_unread
        num HXD_INBOX_RETAIN_READ retain_read
        db=
    fi
    if on HXD_HISTORY on; then
        echo
        echo "[history]"
        [ -z "$db" ] || echo "db = $db"
        num HXD_HISTORY_MAX_LINES max_lines
        num HXD_HISTORY_MAX_DAYS max_days
        db=
    fi
    if on HXD_NEWS on; then
        echo
        echo "[news]"
        [ -z "$db" ] || echo "db = $db"
        echo "blobs = \"$DATA/news-blobs\""
        num HXD_NEWS_RETAIN_DAYS retain_days
        db=
    fi
    if on HXD_MEDIA on; then
        echo
        echo "[media]"
    fi

    if [ -n "${HXD_PUSH_CONTACT:-}" ]; then
        $ng || die "HXD_PUSH_CONTACT needs HXD_NG: devices register over the ng wire"
        echo
        echo "[push]"
        kv contact "$HXD_PUSH_CONTACT"
        echo "vapid_key = \"$DATA/vapid.key\""
        [ -z "$db" ] || echo "db = $db"
        str HXD_PUSH_CONTENT content
    fi

    if on HXD_SYSTEM off; then
        echo
        echo "[system]"
        str HXD_SYSTEM_NICK nick
    else
        unused HXD_SYSTEM_NICK "HXD_SYSTEM is off"
    fi

    if [ -n "${HXD_FILES_ROOT:-}" ]; then
        [ -d "$HXD_FILES_ROOT" ] || die "HXD_FILES_ROOT $HXD_FILES_ROOT is not a directory; mount one there"
        echo
        echo "[files]"
        kv root "$HXD_FILES_ROOT"
        echo 'bind = "0.0.0.0:5501"'
        num HXD_FILES_MAX_FILE_SIZE max_file_size
    fi

    # Both files or neither: a certificate without its key is a mistake
    # worth stopping for, not a TLS port quietly left off. A mounted pair
    # wins over a self-signed one, so moving to a CA's certificate is
    # setting the two variables.
    if [ -n "${HXD_TLS_CERT:-}${HXD_TLS_KEY:-}" ]; then
        [ -n "${HXD_TLS_CERT:-}" ] || die "HXD_TLS_KEY needs HXD_TLS_CERT"
        [ -n "${HXD_TLS_KEY:-}" ] || die "HXD_TLS_CERT needs HXD_TLS_KEY"
        [ -r "$HXD_TLS_CERT" ] || die "HXD_TLS_CERT $HXD_TLS_CERT is not readable; mount it there"
        [ -r "$HXD_TLS_KEY" ] || die "HXD_TLS_KEY $HXD_TLS_KEY is not readable by uid $(id -u); mount it there"
        on HXD_TLS_SELF_SIGNED off &&
            echo "hxd-entrypoint: HXD_TLS_SELF_SIGNED ignored: HXD_TLS_CERT is set" >&2
        echo
        echo "[tls]"
        echo 'bind = "0.0.0.0:5600"'
        kv cert "$HXD_TLS_CERT"
        kv key "$HXD_TLS_KEY"
    elif on HXD_TLS_SELF_SIGNED off; then
        # hxd makes the pair on the first start and keeps it in the
        # volume, so the certificate clients pinned survives a recreate.
        (umask 077 && mkdir -p "$DATA/tls")
        echo
        echo "[tls]"
        echo 'bind = "0.0.0.0:5600"'
        echo "cert = \"$DATA/tls/cert.pem\""
        echo "key = \"$DATA/tls/key.pem\""
        echo "self_signed = true"
    fi

    if [ -n "${HXD_VOICE_ADVERTISE:-}" ]; then
        # A concrete bind lets the server tell which advertised address a
        # datagram arrived on, so it can offer a LAN address beside the
        # WAN one; the wildcard allows one address per family.
        voice_bind=${HXD_VOICE_BIND:-0.0.0.0:5504}
        voice_port=${voice_bind##*:}
        case $voice_port in
            "" | *[!0-9]*) die "HXD_VOICE_BIND must be address:port, got $voice_bind" ;;
        esac
        # A bare address gets the voice port.
        advertise=
        old_ifs=$IFS
        IFS=,
        for a in $HXD_VOICE_ADVERTISE; do
            a=$(printf '%s' "$a" | tr -d '[:space:]')
            case $a in
                "") continue ;;
                \[*\]:* | *.*:*) ;;
                *:*) die "HXD_VOICE_ADVERTISE: write an IPv6 address as [addr]:port, got $a" ;;
                *) a=$a:$voice_port ;;
            esac
            advertise="${advertise:+$advertise,}$a"
        done
        IFS=$old_ifs
        echo
        echo "[voice]"
        kv bind "$voice_bind"
        kvlist advertise "$advertise"
        num HXD_VOICE_MAX_PER_ROOM max_per_room
        if on HXD_VIDEO off; then
            echo
            echo "[voice.video]"
        fi
    else
        unused HXD_VOICE_BIND "voice is off without HXD_VOICE_ADVERTISE"
        unused HXD_VOICE_MAX_PER_ROOM "voice is off without HXD_VOICE_ADVERTISE"
        unused HXD_VIDEO "voice is off without HXD_VOICE_ADVERTISE"
    fi

    if [ -n "${HXD_TRACKERS:-}" ]; then
        echo
        echo "[tracker]"
        str HXD_TRACKER_DESCRIPTION description
        num HXD_TRACKER_ADVERTISED_PORT advertised_port
        old_ifs=$IFS
        IFS=,
        for t in $HXD_TRACKERS; do
            t=$(printf '%s' "$t" | tr -d '[:space:]')
            [ -n "$t" ] || continue
            echo
            echo "[[tracker.targets]]"
            kv address "$t"
            echo 'protocol = "v1"'
        done
        IFS=$old_ifs
    else
        unused HXD_TRACKER_DESCRIPTION "no HXD_TRACKERS"
        unused HXD_TRACKER_ADVERTISED_PORT "no HXD_TRACKERS"
    fi

    if [ -n "${HXD_EXTRA_CONFIG:-}" ]; then
        [ -f "$HXD_EXTRA_CONFIG" ] || die "HXD_EXTRA_CONFIG $HXD_EXTRA_CONFIG does not exist"
        # Appended after whichever table was written last, a key before
        # the fragment's first header would land in that table: in [media]
        # on one start and [tracker] on the next. Refused instead.
        awk '/^[[:space:]]*(#|$)/ { next } /^[[:space:]]*\[/ { exit 0 } { exit 1 }' \
            "$HXD_EXTRA_CONFIG" ||
            die "HXD_EXTRA_CONFIG $HXD_EXTRA_CONFIG: put every key under a [section] header"
        echo
        echo "# From $HXD_EXTRA_CONFIG."
        cat "$HXD_EXTRA_CONFIG"
    fi
}

# A fresh volume's accounts directory, before hxd sees it. hxd bootstraps
# the guest account only into a directory that does not exist yet, so
# leaving guests out is creating it empty, and writing the admin into it
# means writing the guest too. That copy mirrors FileAuth::bootstrap's
# text because no hxd subcommand bootstraps without serving; keep the two
# in step.
first_start() {
    accounts=$DATA/accounts
    [ ! -e "$accounts" ] || return 0
    if on HXD_GUEST on; then
        [ -n "${HXD_ADMIN_LOGIN:-}" ] || return 0
        (umask 077 && mkdir "$accounts")
        (umask 077 && cat >"$accounts/guest.toml") <<'EOF'
# Default guest account, created on first run. Delete this file
# to disable guest logins.
name = "guest"

[access]
read_chat = true
read_chat_history = true
send_chat = true
create_pchats = true
send_msgs = true
get_user_info = true
use_any_name = true
# Guests may not post images. Uncomment to let them, and
# read docs/inline-media.md first — this is the one bit
# that lets a stranger put a picture on everyone's screen.
# send_media = true
EOF
    else
        (umask 077 && mkdir "$accounts")
    fi
}

# An account with every named bit, written once and never overwritten, so
# a fresh volume has someone who can administer it. Once it exists the
# password is not read, so the variables holding it can go.
admin() {
    login=$HXD_ADMIN_LOGIN
    case $login in
        .* | *[!A-Za-z0-9_.@-]*) die "HXD_ADMIN_LOGIN $login: letters, digits and _ - . @ only" ;;
    esac
    [ ${#login} -le 31 ] || die "HXD_ADMIN_LOGIN is longer than 31 characters"
    # FileAuth folds a login to lower case before it looks for the file.
    login=$(printf '%s' "$login" | tr '[:upper:]' '[:lower:]')
    accounts=$DATA/accounts
    [ ! -e "$accounts/$login.toml" ] || return 0

    if [ -n "${HXD_ADMIN_PASSWORD_FILE:-}" ]; then
        password=$(cat "$HXD_ADMIN_PASSWORD_FILE")
    else
        password=${HXD_ADMIN_PASSWORD:-}
    fi
    [ -n "$password" ] || die "HXD_ADMIN_LOGIN needs HXD_ADMIN_PASSWORD or HXD_ADMIN_PASSWORD_FILE on the start that writes accounts/$login.toml"
    case $password in
        *'
'*) die "the admin password may not contain a newline" ;;
    esac

    first_start
    umask 077
    {
        echo "# Written by hxd-entrypoint from HXD_ADMIN_LOGIN on first start;"
        echo "# the variables are not read again once this file exists."
        kv name "$HXD_ADMIN_LOGIN"
        kv password "$password"
        echo
        echo "[access]"
        for bit in delete_files upload_files download_files rename_files move_files \
            create_folders delete_folders rename_folders move_folders read_chat \
            send_chat create_pchats create_users delete_users read_users modify_users \
            read_news post_news disconnect_users cant_be_disconnected get_user_info \
            upload_anywhere use_any_name dont_show_agreement comment_files \
            comment_folders view_drop_boxes make_aliases can_broadcast delete_articles \
            create_categories delete_categories create_news_bundles \
            delete_news_bundles upload_folders download_folders send_msgs voice_chat \
            read_chat_history send_media video_chat screen_share; do
            echo "$bit = true"
        done
    } >"$accounts/$login.toml"
    echo "hxd-entrypoint: wrote account $login" >&2
}

if [ -f "$HXD_CONFIG" ]; then
    # The file is the operator's, and it may keep its accounts anywhere.
    [ -z "${HXD_ADMIN_LOGIN:-}" ] ||
        echo "hxd-entrypoint: HXD_ADMIN_LOGIN ignored: $HXD_CONFIG is mounted" >&2
    config=$HXD_CONFIG
else
    # Edits to the generated file are lost at the next start, which would
    # be a revocation reported done and then quietly lifted.
    words=
    for arg; do
        case $arg in
            -*) ;;
            *) words="$words $arg" ;;
        esac
    done
    case $words in
        " identity revoke"*) die "identity revoke edits the config file, and this one is written from HXD_* variables at every start. List the fingerprint in HXD_REVOKED_IDENTITIES, or HXD_REVOKED_DEVICES for one device, and recreate the container" ;;
    esac
    if [ -n "${HXD_ADMIN_LOGIN:-}" ]; then
        admin
    else
        first_start
    fi
    tmp=$(mktemp "$GENERATED.XXXXXX")
    trap 'rm -f "$tmp"' EXIT
    generate >"$tmp"
    mv -f "$tmp" "$GENERATED"
    trap - EXIT
    config=$GENERATED
fi

exec hxd --config "$config" "$@"
