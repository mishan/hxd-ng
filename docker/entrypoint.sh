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
set -eu

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

# The container's default gateway: the address a proxy on the host is
# seen from when it reaches the ng port through a published port.
gateway() {
    hex=$(awk '$2 == "00000000" { print $3; exit }' /proc/net/route 2>/dev/null)
    [ ${#hex} -eq 8 ] || return 0
    # /proc/net/route prints the address in host byte order: little-endian.
    printf '%d.%d.%d.%d' "0x${hex#??????}" "0x$(echo "$hex" | cut -c5-6)" \
        "0x$(echo "$hex" | cut -c3-4)" "0x$(echo "$hex" | cut -c1-2)"
}

# The addresses the ng port should believe X-Forwarded-For from, with
# `gateway` standing for the container's default gateway.
trusted_proxies() {
    out=
    old_ifs=$IFS
    IFS=,
    for item in $1; do
        item=$(printf '%s' "$item" | tr -d '[:space:]')
        case $item in
            "" | none) continue ;;
            gateway) item=$(gateway) && [ -n "$item" ] || continue ;;
        esac
        out="${out:+$out,}$item"
    done
    IFS=$old_ifs
    kvlist trusted_proxies "$out"
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
        echo 'bind = "0.0.0.0:5700"'
        num HXD_NG_GRACE grace
        num HXD_NG_MAX_DETACHED_PER_ADDR max_detached_per_addr
        trusted_proxies "${HXD_NG_TRUSTED_PROXIES-127.0.0.1,::1,gateway}"
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
    fi

    if [ -n "${HXD_FILES_ROOT:-}" ]; then
        [ -d "$HXD_FILES_ROOT" ] || die "HXD_FILES_ROOT $HXD_FILES_ROOT is not a directory; mount one there"
        echo
        echo "[files]"
        kv root "$HXD_FILES_ROOT"
        echo 'bind = "0.0.0.0:5501"'
        num HXD_FILES_MAX_FILE_SIZE max_file_size
    fi

    if [ -n "${HXD_VOICE_ADVERTISE:-}" ]; then
        # A bare address gets the container's voice port.
        advertise=
        old_ifs=$IFS
        IFS=,
        for a in $HXD_VOICE_ADVERTISE; do
            a=$(printf '%s' "$a" | tr -d '[:space:]')
            case $a in
                "") continue ;;
                \[*\]:* | *.*:*) ;;
                *:*) die "HXD_VOICE_ADVERTISE: write an IPv6 address as [addr]:port, got $a" ;;
                *) a=$a:5504 ;;
            esac
            advertise="${advertise:+$advertise,}$a"
        done
        IFS=$old_ifs
        echo
        echo "[voice]"
        echo 'bind = "0.0.0.0:5504"'
        kvlist advertise "$advertise"
        num HXD_VOICE_MAX_PER_ROOM max_per_room
        if on HXD_VIDEO off; then
            echo
            echo "[voice.video]"
        fi
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
    fi

    if [ -n "${HXD_EXTRA_CONFIG:-}" ]; then
        [ -f "$HXD_EXTRA_CONFIG" ] || die "HXD_EXTRA_CONFIG $HXD_EXTRA_CONFIG does not exist"
        echo
        echo "# From $HXD_EXTRA_CONFIG."
        cat "$HXD_EXTRA_CONFIG"
    fi
}

# An account with every named bit, written once and never overwritten, so
# a fresh volume has someone who can administer it. hxd only bootstraps
# the guest account into a directory that does not exist yet, so on a
# first start this writes that guest too (FileAuth::bootstrap's).
admin() {
    login=$HXD_ADMIN_LOGIN
    case $login in
        .* | *[!A-Za-z0-9_.@-]*) die "HXD_ADMIN_LOGIN $login: letters, digits and _ - . @ only" ;;
    esac
    [ ${#login} -le 31 ] || die "HXD_ADMIN_LOGIN is longer than 31 characters"
    if [ -n "${HXD_ADMIN_PASSWORD_FILE:-}" ]; then
        password=$(cat "$HXD_ADMIN_PASSWORD_FILE")
    else
        password=${HXD_ADMIN_PASSWORD:-}
    fi
    [ -n "$password" ] || die "HXD_ADMIN_LOGIN needs HXD_ADMIN_PASSWORD or HXD_ADMIN_PASSWORD_FILE"
    case $password in
        *'
'*) die "the admin password may not contain a newline" ;;
    esac

    accounts=$DATA/accounts
    [ ! -e "$accounts/$login.toml" ] || return 0
    umask 077
    if [ ! -d "$accounts" ]; then
        mkdir -p "$accounts"
        if on HXD_GUEST on; then
            cat >"$accounts/guest.toml" <<'EOF'
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
        fi
    fi
    {
        echo "# Written by hxd-entrypoint from HXD_ADMIN_LOGIN on first start;"
        echo "# the variables are not read again once this file exists."
        kv name "$login"
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
    [ -z "${HXD_ADMIN_LOGIN:-}" ] || admin
    tmp=$(mktemp "$GENERATED.XXXXXX")
    trap 'rm -f "$tmp"' EXIT
    generate >"$tmp"
    mv -f "$tmp" "$GENERATED"
    trap - EXIT
    config=$GENERATED
fi

exec hxd --config "$config" "$@"
