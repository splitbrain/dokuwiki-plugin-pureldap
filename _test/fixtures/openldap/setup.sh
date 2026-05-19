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

# Wait for slapd to bind. osixia's bootstrap finishes before post_start
# in practice, but be defensive.
echo "[openldap/setup] waiting for slapd..."
for i in $(seq 1 60); do
    if ldapwhoami -x -H ldap://localhost >/dev/null 2>&1 || \
       [ ! -x /usr/bin/ldapwhoami ]; then
        # If ldapwhoami doesn't exist yet, fall through to the install step;
        # we'll re-check below.
        break
    fi
    sleep 1
done

if ! command -v ldapadd >/dev/null 2>&1; then
    echo "[openldap/setup] installing ldap-utils..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y --no-install-recommends -qq ldap-utils
fi

# Re-wait now that ldapwhoami is available.
for i in $(seq 1 60); do
    if ldapwhoami -x -H ldap://localhost >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

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
