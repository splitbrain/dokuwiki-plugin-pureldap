#!/usr/bin/env bash
# Runs once at container start via compose post_start. Installs the
# ldap-utils package (osixia/openldap doesn't ship it) and creates
# the two OUs the provisioner writes into.
set -euo pipefail

HOST="localhost"
PORT="389"
BIND_DN="cn=admin,dc=example,dc=com"
BIND_PW="Foo_b_ar123!"
BASE="dc=example,dc=com"

if ! command -v ldapadd >/dev/null 2>&1; then
    echo "[openldap setup] installing ldap-utils..."
    DEBIAN_FRONTEND=noninteractive apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends ldap-utils
fi

# Wait for slapd to become responsive (image's own entrypoint starts it).
echo "[openldap setup] waiting for slapd..."
for _ in $(seq 1 60); do
    if ldapsearch -x -H "ldap://${HOST}:${PORT}" -D "${BIND_DN}" -w "${BIND_PW}" \
        -b "${BASE}" -s base "(objectClass=*)" dn >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

add_ou() {
    local ou="$1"
    local dn="ou=${ou},${BASE}"
    if ldapsearch -x -H "ldap://${HOST}:${PORT}" -D "${BIND_DN}" -w "${BIND_PW}" \
        -b "${dn}" -s base "(objectClass=*)" dn >/dev/null 2>&1; then
        echo "[openldap setup] ${dn} already exists"
        return
    fi
    echo "[openldap setup] creating ${dn}"
    ldapadd -x -H "ldap://${HOST}:${PORT}" -D "${BIND_DN}" -w "${BIND_PW}" <<EOF
dn: ${dn}
objectClass: organizationalUnit
ou: ${ou}
EOF
}

add_ou People
add_ou Groups

echo "[openldap setup] done"
