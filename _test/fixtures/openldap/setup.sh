#!/usr/bin/env bash
# Invoked once by the workflow (or by hand) via `docker exec` once the
# openldap container is up. Installs the ldap-utils package (osixia
# doesn't ship it), waits for slapd, then creates the two OUs the
# provisioner writes into.
set -euxo pipefail

HOST="localhost"
PORT="389"
BIND_DN="cn=admin,dc=example,dc=com"
BIND_PW="Foo_b_ar123!"
BASE="dc=example,dc=com"

if ! command -v ldapadd >/dev/null 2>&1; then
    echo "[openldap setup] installing ldap-utils..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y --no-install-recommends ldap-utils
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
