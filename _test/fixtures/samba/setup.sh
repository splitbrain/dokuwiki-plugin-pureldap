#!/bin/bash
# One-shot pre-provisioning setup for the Samba AD-DC fixture.
#
# Runs inside pureldap-samba via the compose post_start hook BEFORE
# provision.py. Three responsibilities:
#
#   1. Wait for samba-tool to start responding. Samba's first-boot
#      domain provisioning takes 30-90s; the post_start hook fires
#      right after the container's main process starts, so the daemon
#      isn't ready yet when we begin.
#   2. Set the domain password policy:
#      - max-pwd-age=42 pins the value that
#        ADClientTest::testMaxPasswordAge asserts on.
#      - min-pwd-age=0 lets testSetPassword's user-initiated change
#        succeed (AD's default 1-day floor blocks it).
#      - history-length=0 lets testSetPassword be re-run against the
#        same fixture without tripping the reuse check on the second
#        pass.
#   3. Install the TLS cert produced by the tls-init service.
#      The cert covers localhost / 127.0.0.1 / dc1.example.com so
#      FreeDSx's STARTTLS hostname check accepts the connection.

set -euo pipefail

echo "[samba/setup] waiting for samba-tool to respond..."
for i in $(seq 1 150); do
    if samba-tool user list >/dev/null 2>&1; then
        break
    fi
    sleep 2
done

if ! samba-tool user list >/dev/null 2>&1; then
    echo "[samba/setup] samba-tool never responded within 300s" >&2
    exit 1
fi

# `user list` can succeed before the domain is fully provisioned for
# writes (admin password change, password policy). Retry the policy
# change until samba accepts it.
echo "[samba/setup] setting domain password policy..."
for i in $(seq 1 60); do
    if samba-tool domain passwordsettings set \
            --max-pwd-age=42 --min-pwd-age=0 --history-length=0 \
            >/dev/null 2>&1; then
        break
    fi
    sleep 2
done
PWSETTINGS=$(samba-tool domain passwordsettings show)
if ! grep -q "Maximum password age (days): 42" <<<"$PWSETTINGS" \
        || ! grep -q "Minimum password age (days): 0" <<<"$PWSETTINGS" \
        || ! grep -q "Password history length: 0" <<<"$PWSETTINGS"; then
    echo "[samba/setup] domain passwordsettings never accepted within 120s" >&2
    samba-tool domain passwordsettings set \
        --max-pwd-age=42 --min-pwd-age=0 --history-length=0 || true
    exit 1
fi

echo "[samba/setup] installing TLS cert from /certs..."
TLS_DIR=/var/lib/samba/private/tls
mkdir -p "$TLS_DIR"
cp /certs/cert.pem "$TLS_DIR/cert.pem"
cp /certs/key.pem  "$TLS_DIR/key.pem"
cp /certs/ca.pem   "$TLS_DIR/ca.pem"
chmod 600 "$TLS_DIR/key.pem"
pkill -HUP samba || true

echo "[samba/setup] done."
