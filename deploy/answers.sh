# Airgapp install answers, shared by setup.sh and first-boot provisioning.
# Sourced, not run. Works in bash 3.2+ (so its test runs on a Mac too).
#
# Answers are NAMED, so a question added later (or the WAN question, asked
# only when the LTE modem isn't found) can never shift the others:
#
#   WIFI_NAME=Airgapp         hotspot name                      default Airgapp
#   WIFI_PASSWORD=            hotspot password, 8-63 chars      generated if empty
#   WIFI_COUNTRY=US           ISO 3166-1 code (or 00)           default US
#   WIFI_CHANNEL=36           36 (5 GHz) or 1-14 (2.4 GHz)      default 36
#   ADMIN_PASSWORD=           console password, 8+ chars        generated if empty
#   WAN_INTERFACE=            only if the LTE modem isn't found
#
# There is no universal password. One left empty is generated and written to
# $AIRGAPP_CREDENTIALS_FILE (first boot points it at the card's boot
# partition, so it can be read on a computer). An old four-line answers file
# (name, password, country, admin password) is still understood.
#
#   load_answers FILE   read FILE into the environment (a missing file is fine);
#                       a value already in the environment wins
#   resolve_answers     fill in the rest (asking on a terminal, else defaults),
#                       generate missing passwords, check everything

AIRGAPP_ANSWER_KEYS="WIFI_NAME WIFI_PASSWORD WIFI_COUNTRY WIFI_CHANNEL ADMIN_PASSWORD WAN_INTERFACE"

answers_error() { echo "[ERROR] $1" >&2; return 1; }

load_answers() {
    local file=$1 line key value named=0 n=0 legacy1="" legacy2="" legacy3="" legacy4=""
    [ -f "$file" ] || return 0
    while IFS= read -r line || [ -n "$line" ]; do
        line=${line%$'\r'}
        case "$line" in ''|'#'*) continue ;; esac
        key=${line%%=*}
        key=${key%"${key##*[! ]}"}            # trailing spaces
        if [ "$key" != "$line" ] && printf '%s' "$key" | grep -qE '^[A-Z_]+$'; then
            named=1
            value=${line#*=}
            value=${value#"${value%%[! ]*}"}  # leading spaces
            case " $AIRGAPP_ANSWER_KEYS " in
                *" $key "*) [ -n "$(eval "printf '%s' \"\${$key:-}\"")" ] || export "$key=$value" ;;
            esac
        else
            n=$((n + 1))
            case $n in 1) legacy1=$line ;; 2) legacy2=$line ;; 3) legacy3=$line ;; 4) legacy4=$line ;; esac
        fi
    done <"$file"
    if [ $named -eq 0 ] && [ $n -gt 0 ]; then
        # The old positional file: name, wifi password, country, admin password.
        [ -n "${WIFI_NAME:-}" ] || export WIFI_NAME="$legacy1"
        [ -n "${WIFI_PASSWORD:-}" ] || export WIFI_PASSWORD="$legacy2"
        [ -n "${WIFI_COUNTRY:-}" ] || export WIFI_COUNTRY="$legacy3"
        [ -n "${ADMIN_PASSWORD:-}" ] || export ADMIN_PASSWORD="$legacy4"
    fi
    return 0
}

# A 16-character password from an alphabet without look-alikes (no 0/O, 1/l/I).
# Reads a fixed amount of randomness, so no pipe is ever cut short (safe under
# `set -o pipefail`).
generate_password() {
    head -c 600 /dev/urandom | LC_ALL=C tr -dc 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789' | cut -c1-16
}

# ask VAR PROMPT DEFAULT [secret]: keep a given value; else ask on a terminal; else the default.
ask_answer() {
    local var=$1 prompt=$2 def=$3 secret=${4:-} reply=""
    [ -z "$(eval "printf '%s' \"\${$var:-}\"")" ] || return 0
    if [ -t 0 ] && [ -z "${AIRGAPP_NONINTERACTIVE:-}" ]; then
        if [ -n "$secret" ]; then
            read -rsp "$prompt: " reply; echo
        else
            read -rp "$prompt [$def]: " reply
        fi
    fi
    export "$var=${reply:-$def}"
}

resolve_answers() {
    ask_answer WIFI_NAME "Hotspot (Wi-Fi) name" "Airgapp"
    ask_answer WIFI_PASSWORD "Hotspot password, 8+ characters (Enter to generate one)" "" secret
    ask_answer WIFI_COUNTRY "Wi-Fi country code (ISO 3166-1, e.g. US, GB, GR)" "US"
    ask_answer WIFI_CHANNEL "Hotspot channel: 36 (5 GHz, recommended) or 6 (2.4 GHz)" "36"
    ask_answer ADMIN_PASSWORD "Console admin password, 8+ characters (Enter to generate one)" "" secret
    WIFI_COUNTRY=$(printf '%s' "$WIFI_COUNTRY" | tr '[:lower:]' '[:upper:]')
    export WIFI_COUNTRY

    AIRGAPP_GENERATED=""
    if [ -z "$WIFI_PASSWORD" ]; then WIFI_PASSWORD=$(generate_password); export WIFI_PASSWORD; AIRGAPP_GENERATED="$AIRGAPP_GENERATED WIFI_PASSWORD"; fi
    if [ -z "$ADMIN_PASSWORD" ]; then ADMIN_PASSWORD=$(generate_password); export ADMIN_PASSWORD; AIRGAPP_GENERATED="$AIRGAPP_GENERATED ADMIN_PASSWORD"; fi

    [ ${#WIFI_NAME} -ge 1 ] && [ ${#WIFI_NAME} -le 32 ] || answers_error "WIFI_NAME must be 1-32 characters" || return 1
    [ ${#WIFI_PASSWORD} -ge 8 ] && [ ${#WIFI_PASSWORD} -le 63 ] || answers_error "WIFI_PASSWORD must be 8-63 characters (WPA2)" || return 1
    printf '%s' "$WIFI_COUNTRY" | grep -qE '^([A-Z]{2}|00)$' || answers_error "WIFI_COUNTRY must be a two-letter country code (e.g. US, GB, GR), got '$WIFI_COUNTRY'" || return 1
    printf '%s' "$WIFI_CHANNEL" | grep -qE '^[0-9]+$' && { [ "$WIFI_CHANNEL" -ge 1 ] && [ "$WIFI_CHANNEL" -le 14 ] || [ "$WIFI_CHANNEL" -ge 36 ] && [ "$WIFI_CHANNEL" -le 165 ]; } \
        || answers_error "WIFI_CHANNEL must be 1-14 (2.4 GHz) or 36-165 (5 GHz), got '$WIFI_CHANNEL'" || return 1
    [ ${#ADMIN_PASSWORD} -ge 8 ] || answers_error "ADMIN_PASSWORD must be at least 8 characters" || return 1

    if [ -n "$AIRGAPP_GENERATED" ] && [ -n "${AIRGAPP_CREDENTIALS_FILE:-}" ]; then
        {
            echo "# Airgapp: passwords generated at setup, $(date '+%Y-%m-%d %H:%M')."
            echo "# Keep them somewhere safe, then delete this file."
            echo "WIFI_NAME=$WIFI_NAME"
            case "$AIRGAPP_GENERATED" in *WIFI_PASSWORD*) echo "WIFI_PASSWORD=$WIFI_PASSWORD" ;; esac
            echo "ADMIN_USER=admin"
            case "$AIRGAPP_GENERATED" in *ADMIN_PASSWORD*) echo "ADMIN_PASSWORD=$ADMIN_PASSWORD" ;; esac
        } >"$AIRGAPP_CREDENTIALS_FILE" || answers_error "could not write $AIRGAPP_CREDENTIALS_FILE" || return 1
        chmod 600 "$AIRGAPP_CREDENTIALS_FILE" 2>/dev/null || true
    fi
    return 0
}
