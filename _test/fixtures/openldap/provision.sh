#!/bin/bash
# Fixture readiness contract for the OpenLDAP target.
#
# The osixia/openldap image loads bootstrap.ldif automatically on first
# boot via its /container/service/slapd/assets/config/bootstrap/ldif
# mount, so there's no post-boot setup to run — this script just waits
# for slapd to open its port, gives it a moment to finish ingesting
# the LDIF, and verifies that the bootstrap data is actually queryable.
#
# Exits non-zero (with an Actions-friendly ::error:: line) if the
# fixture didn't come up or the bootstrap didn't land.

set -e

PORT=1389
COMPOSE=_test/docker-compose.openldap.yml

echo "Waiting for OpenLDAP on port ${PORT}..."
for i in $(seq 1 120); do
    if (echo > /dev/tcp/localhost/${PORT}) 2>/dev/null; then
        echo "Port open after ${i}s"
        break
    fi
    sleep 1
done
if ! (echo > /dev/tcp/localhost/${PORT}) 2>/dev/null; then
    echo "::error::OpenLDAP did not open port ${PORT} within 120s"
    docker compose -f "$COMPOSE" logs --tail=200
    exit 1
fi

# slapd needs a moment after the port opens to finish ingesting the
# bootstrap LDIF.
sleep 8

if ! ldapsearch -x -H "ldap://localhost:${PORT}" \
        -b dc=example,dc=org \
        -D cn=admin,dc=example,dc=org \
        -w adminpass \
        '(uid=alice)' uid mail 2>/dev/null \
        | grep -q '^uid: alice'; then
    echo "::error::Bootstrap LDIF did not load (alice not found)"
    docker compose -f "$COMPOSE" logs --tail=200
    exit 1
fi

echo "Fixture verified — alice is searchable on ${PORT}"
