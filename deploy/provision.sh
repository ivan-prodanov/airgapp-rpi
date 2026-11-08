#!/bin/bash
# Airgapp first-boot setup. Run once by netfilter-provision.service.
# Expects on the boot partition (mounted at /boot/firmware):
#   airgapp/netfilterd       the pre-built arm64 binary
#   airgapp/deploy/*         the full deploy/ directory
#   airgapp/answers.txt      optional named answers (see deploy/answers.sh)
# (A card prepared by an older prepare-sd.sh uses netfilter/ instead; it still works.)
#
# Passwords left empty in answers.txt are generated and written to
# airgapp-credentials.txt at the top of the boot partition, so they can be
# read by putting the card in a computer. On success writes
# /var/lib/netfilter-provisioned and disables itself.

set -euo pipefail

LOCK=/var/lib/netfilter-provisioned
[[ -f $LOCK ]] && { echo "Already set up; nothing to do."; exit 0; }

SRC=""
for d in /boot/firmware/airgapp /boot/firmware/netfilter /boot/airgapp /boot/netfilter; do
    [[ -d "$d/deploy" ]] && { SRC=$d; break; }
done
[[ -n "$SRC" ]] || { echo "No airgapp/deploy on the boot partition — re-run scripts/prepare-sd.sh"; exit 1; }
[[ -f "$SRC/netfilterd" ]] || { echo "No $SRC/netfilterd binary"; exit 1; }

echo "=== Airgapp first-boot setup $(date -Iseconds) (from $SRC) ==="

mkdir -p /tmp/deploy
cp -f "$SRC/deploy"/* /tmp/deploy/
chmod +x /tmp/deploy/setup.sh
install -m 0755 "$SRC/netfilterd" /tmp/netfilterd

# Named answers into the environment (an old four-line file still works);
# setup.sh asks nothing here, it uses them, the defaults, and generated passwords.
# shellcheck source=answers.sh
. /tmp/deploy/answers.sh
load_answers "$SRC/answers.txt"
export AIRGAPP_CREDENTIALS_FILE="${SRC%/*}/airgapp-credentials.txt"
export AIRGAPP_NONINTERACTIVE=1

bash /tmp/deploy/setup.sh </dev/null

mkdir -p /var/lib
touch "$LOCK"
systemctl disable netfilter-provision.service
echo "=== First-boot setup complete ==="
