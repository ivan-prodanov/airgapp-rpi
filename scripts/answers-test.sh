#!/bin/bash
# Tests for deploy/answers.sh, the install answers shared by setup.sh and
# first-boot provisioning. No root, no Pi: run it anywhere with bash 3.2+.
#   bash scripts/answers-test.sh
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
FAILS=0

check() { # name want got
    if [ "$2" = "$3" ]; then echo "  ok    $1"; else echo "  FAIL  $1: want [$2] got [$3]"; FAILS=$((FAILS + 1)); fi
}
yes_if() { # name command...: passes when the command succeeds
    local name=$1; shift
    if "$@"; then echo "  ok    $name"; else echo "  FAIL  $name"; FAILS=$((FAILS + 1)); fi
}
absent() { [ ! -e "$1" ]; }
differ() { [ "$1" != "$2" ]; }
has_lines() { local f=$1 l; shift; for l in "$@"; do grep -qxF "$l" "$f" || return 1; done; }
lacks() { ! grep -qi "$1" "$2"; }
alphabet_ok() { printf '%s' "$1" | grep -qE '^[A-HJ-NP-Za-km-z2-9]+$'; }
refused() { # line word: resolving a file holding just this line fails, and says word
    local err
    printf '%s\n' "$1" >"$TMP/bad"
    err=$(resolve "$TMP/bad" 2>&1 >/dev/null) && return 1
    printf '%s' "$err" | grep -qi "$2"
}

# Load and resolve an answers file in a clean subshell; print the result as KEY=value lines.
resolve() { # file [creds-file]
    (
        unset WIFI_NAME WIFI_PASSWORD WIFI_COUNTRY WIFI_CHANNEL ADMIN_PASSWORD WAN_INTERFACE
        export AIRGAPP_CREDENTIALS_FILE="${2:-$TMP/creds}"
        . "$ROOT/deploy/answers.sh"
        load_answers "$1" && resolve_answers </dev/null || exit $?
        for k in WIFI_NAME WIFI_PASSWORD WIFI_COUNTRY WIFI_CHANNEL ADMIN_PASSWORD WAN_INTERFACE; do
            eval "printf '%s=%s\n' \"\$k\" \"\${$k:-}\""
        done
    )
}
val() { printf '%s\n' "$1" | sed -n "s/^$2=//p"; }

echo "named answers are used as given"
cat >"$TMP/a1" <<'EOF'
# a comment
WIFI_NAME=Car Wi-Fi
WIFI_PASSWORD=correct horse battery
WIFI_COUNTRY=GR
WIFI_CHANNEL=6
ADMIN_PASSWORD=adminpass123
WAN_INTERFACE=enx001122
EOF
rm -f "$TMP/creds"; out=$(resolve "$TMP/a1")
check "name" "Car Wi-Fi" "$(val "$out" WIFI_NAME)"
check "wifi password" "correct horse battery" "$(val "$out" WIFI_PASSWORD)"
check "country" "GR" "$(val "$out" WIFI_COUNTRY)"
check "channel" "6" "$(val "$out" WIFI_CHANNEL)"
check "admin password" "adminpass123" "$(val "$out" ADMIN_PASSWORD)"
check "wan interface" "enx001122" "$(val "$out" WAN_INTERFACE)"
yes_if "nothing generated, so no credentials file" absent "$TMP/creds"

echo "nothing given: Airgapp, defaults, and generated passwords written down"
: >"$TMP/a2"; rm -f "$TMP/creds"; out=$(resolve "$TMP/a2")
check "name defaults to Airgapp" "Airgapp" "$(val "$out" WIFI_NAME)"
check "country defaults to US" "US" "$(val "$out" WIFI_COUNTRY)"
check "channel defaults to 36" "36" "$(val "$out" WIFI_CHANNEL)"
wp=$(val "$out" WIFI_PASSWORD); ap=$(val "$out" ADMIN_PASSWORD)
check "wifi password is 16 characters" "16" "${#wp}"
check "admin password is 16 characters" "16" "${#ap}"
yes_if "generated from an unambiguous alphabet" alphabet_ok "$wp$ap"
yes_if "the two passwords differ" differ "$wp" "$ap"
yes_if "both written to the credentials file" has_lines "$TMP/creds" "WIFI_PASSWORD=$wp" "ADMIN_PASSWORD=$ap" "ADMIN_USER=admin"
yes_if "no old default anywhere" lacks "changeme\|netfilter" "$TMP/creds"
out2=$(resolve "$TMP/a2" "$TMP/creds2")
yes_if "a second install gets different passwords" differ "$(val "$out2" WIFI_PASSWORD)" "$wp"
out3=$(resolve "$TMP/does-not-exist" "$TMP/creds3")
check "a missing answers file means all defaults" "Airgapp" "$(val "$out3" WIFI_NAME)"

echo "an old four-line answers file still means what it meant"
printf 'NetFilter\nchangeme123\nUS\nnetfilter\n' >"$TMP/a3"; out=$(resolve "$TMP/a3")
check "line 1 is the name" "NetFilter" "$(val "$out" WIFI_NAME)"
check "line 2 is the wifi password" "changeme123" "$(val "$out" WIFI_PASSWORD)"
check "line 3 is the country" "US" "$(val "$out" WIFI_COUNTRY)"
check "line 4 is the admin password" "netfilter" "$(val "$out" ADMIN_PASSWORD)"
check "and the channel is not shifted into" "36" "$(val "$out" WIFI_CHANNEL)"

echo "edited on Windows (CRLF) and spaces around ="
printf 'WIFI_NAME = Spaced\r\nWIFI_PASSWORD=crlfpass99\r\nWIFI_COUNTRY=gr\r\n' >"$TMP/a4"; out=$(resolve "$TMP/a4")
check "no carriage return, spaces trimmed" "Spaced" "$(val "$out" WIFI_NAME)"
check "password without carriage return" "crlfpass99" "$(val "$out" WIFI_PASSWORD)"
check "country upper-cased" "GR" "$(val "$out" WIFI_COUNTRY)"

echo "values are data, never run"
cat >"$TMP/a5" <<'EOF'
WIFI_NAME=$(touch pwned)
WIFI_PASSWORD=it's "quoted" $HOME; \back=slash
UNKNOWN_KEY=ignored
EOF
out=$(cd "$TMP" && resolve "$TMP/a5")
yes_if "nothing executed" absent "$TMP/pwned"
# shellcheck disable=SC2016 # the dollar is the point: it must stay literal
check "name kept literally" '$(touch pwned)' "$(val "$out" WIFI_NAME)"
check "password kept literally" "it's \"quoted\" \$HOME; \\back=slash" "$(val "$out" WIFI_PASSWORD)"

echo "bad answers stop the install with a reason"
for case in "WIFI_CHANNEL=netfilter|channel" "WIFI_CHANNEL=200|channel" "WIFI_PASSWORD=short|8" "WIFI_COUNTRY=Greece|country" "ADMIN_PASSWORD=abc|8"; do
    line=${case%%|*}; word=${case##*|}
    yes_if "$line is refused, mentioning $word" refused "$line" "$word"
done

echo
if [ $FAILS -eq 0 ]; then echo "PASS"; else echo "FAIL ($FAILS)"; exit 1; fi
