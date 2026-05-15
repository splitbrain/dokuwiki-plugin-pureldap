#!/bin/bash
# Regenerate both fixture artifacts from people.json.
#
# Run this whenever you edit people.json. CI runs it too and `git
# diff --exit-code`s the result, so a stale artifact fails the build.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"

python3 "$HERE/render.py" --target openldap > "$HERE/openldap/bootstrap.ldif"
python3 "$HERE/render.py" --target samba    > "$HERE/samba/provision-data.sh"

echo "Regenerated:"
echo "  $HERE/openldap/bootstrap.ldif"
echo "  $HERE/samba/provision-data.sh"
