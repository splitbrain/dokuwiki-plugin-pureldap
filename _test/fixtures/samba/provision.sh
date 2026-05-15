#!/bin/bash
# Fixture readiness contract for the Samba AD-DC target.
#
# Unlike OpenLDAP (which loads bootstrap.ldif via the image's auto-init
# directory), Samba can't provision custom users/groups until samba-tool
# is responsive — which only happens after the domain has been
# provisioned, well after `docker compose up -d` returns. So this script:
#
#   1. waits for LDAP port 7389 to open (first-boot can take 30-90s)
#   2. docker-execs the in-container provision script, which creates the
#      named users, groups, password policy, and the TLS cert
#   3. sanity-probes via ldapsearch
#
# Exits non-zero (with an Actions-friendly ::error:: line) on any failure.

set -e

PORT=7389
CONTAINER=pureldap-samba
COMPOSE=_test/docker-compose.samba.yml

echo "Waiting for Samba AD-DC on port ${PORT}..."
for i in $(seq 1 240); do
    if (echo > /dev/tcp/localhost/${PORT}) 2>/dev/null; then
        echo "Port open after ${i}s"
        break
    fi
    sleep 1
done
if ! (echo > /dev/tcp/localhost/${PORT}) 2>/dev/null; then
    echo "::error::Samba did not open port ${PORT} within 240s"
    docker compose -f "$COMPOSE" logs --tail=200
    exit 1
fi

echo "Running in-container provisioning..."
docker exec "$CONTAINER" /provision-fixture.sh

# Give samba a moment to settle after the TLS cert regeneration that
# the in-container script does at the end.
sleep 5

if ! ldapsearch -x -H "ldap://localhost:${PORT}" \
        -b "DC=example,DC=local" \
        -D "Administrator@example.local" \
        -w "Vagrantvagrantvagrant1" \
        "(sAMAccountName=a.legrand)" \
        sAMAccountName mail mobile 2>/dev/null \
        | tee /tmp/probe.out \
        | grep -q '^sAMAccountName: a.legrand'; then
    echo "::error::Fixture sanity probe failed (a.legrand not searchable)"
    cat /tmp/probe.out || true
    docker logs "$CONTAINER" --tail=200
    exit 1
fi
if ! grep -q '^mail: a.legrand@example.com' /tmp/probe.out; then
    echo "::error::a.legrand is searchable but mail attribute is missing"
    cat /tmp/probe.out
    exit 1
fi

echo "Fixture verified — a.legrand is searchable on ${PORT}"
