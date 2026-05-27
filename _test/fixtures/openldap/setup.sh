#!/bin/bash
# One-shot pre-provisioning setup for the OpenLDAP fixture.
#
# Runs inside pureldap-openldap via the compose post_start hook BEFORE
# provision.py. Three responsibilities:
#
#   1. Ensure ldap-utils is installed. osixia/openldap doesn't always
#      ship the client tools, and provision.py shells out to ldapadd /
#      ldapmodify. Gated on `command -v` so re-runs are no-ops.
#   2. Seed the ou=People / ou=Groups containers. osixia creates the
#      dc=… root from LDAP_DOMAIN but no sub-OUs, and the LDIFs we
#      emit later assume those parents exist.
#   3. Load the memberof overlay so user entries get a synthesised
#      memberOf attribute. Configured for our group layout (posixGroup
#      with the `member` attribute populated by the provisioner)
#      so LDAPClientTest::testGetUserViaMemberOfStrategy can run.

set -euo pipefail

ADMIN_DN="cn=admin,dc=example,dc=com"
ADMIN_PW="Foo_b_ar123!"
BASE="dc=example,dc=com"
PEOPLE_OU="ou=People,${BASE}"
GROUPS_OU="ou=Groups,${BASE}"

# Install ldap-utils if missing. osixia/openldap doesn't always ship
# the client tools, and provision.py shells out to ldapadd / ldapmodify.
if ! command -v ldapadd >/dev/null 2>&1; then
    echo "[openldap/setup] installing ldap-utils..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y --no-install-recommends -qq ldap-utils
fi

# Wait for slapd to settle. osixia/openldap brings slapd up to apply
# bootstrap LDIFs, then stops and restarts it under its process
# supervisor before the container is fully steady. ldapwhoami can
# briefly succeed against the bootstrap slapd and then fail seconds
# later with "Can't contact LDAP server" while the restart happens.
# We require slapd's PID to be unchanged AND ldapwhoami to keep
# succeeding for several consecutive seconds before proceeding.
echo "[openldap/setup] waiting for slapd to settle..."
prev_pid=""
stable=0
for i in $(seq 1 120); do
    cur_pid=$(pgrep -d, slapd 2>/dev/null || true)
    if [ -n "$cur_pid" ] && [ "$cur_pid" = "$prev_pid" ] \
            && ldapwhoami -x -H ldap://localhost >/dev/null 2>&1; then
        stable=$((stable + 1))
        if [ "$stable" -ge 5 ]; then break; fi
    else
        stable=0
    fi
    prev_pid="$cur_pid"
    sleep 1
done
if [ "$stable" -lt 5 ]; then
    echo "[openldap/setup] slapd never stabilised within 120s" >&2
    exit 1
fi

ensure_ou() {
    local dn="$1" rdn_val="$2"
    if ldapsearch -x -H ldap://localhost -D "$ADMIN_DN" -w "$ADMIN_PW" \
            -b "$dn" -s base -LLL '(objectClass=*)' dn >/dev/null 2>&1; then
        return 0
    fi
    ldapadd -x -H ldap://localhost -D "$ADMIN_DN" -w "$ADMIN_PW" <<EOF
dn: ${dn}
objectClass: organizationalUnit
ou: ${rdn_val}
EOF
}

ensure_ou "$PEOPLE_OU" "People"
ensure_ou "$GROUPS_OU" "Groups"

# Configure the memberof overlay (idempotent).
#
# osixia/openldap ships with memberof already loaded but configured for
# groupOfUniqueNames + uniqueMember. We need it pointing at our group
# layout instead: posixGroup (the structural class on our group
# entries) and `member` (the DN-typed attribute provision.py writes
# alongside memberUid). Replacing values that already match raises
# LDAP_UNWILLING_TO_PERFORM, so gate on the current GroupOC value.
if ! ldapsearch -Y EXTERNAL -H ldapi:/// -b cn=config -LLL \
        '(olcOverlay=memberof)' olcMemberOfGroupOC 2>/dev/null \
        | grep -qi 'olcMemberOfGroupOC: posixGroup'; then
    echo "[openldap/setup] reconfiguring memberof overlay for posixGroup..."
    ldapmodify -Y EXTERNAL -H ldapi:/// <<'EOF'
dn: olcOverlay={0}memberof,olcDatabase={1}mdb,cn=config
changetype: modify
replace: olcMemberOfGroupOC
olcMemberOfGroupOC: posixGroup
-
replace: olcMemberOfMemberAD
olcMemberOfMemberAD: member
EOF
fi

echo "[openldap/setup] done."
