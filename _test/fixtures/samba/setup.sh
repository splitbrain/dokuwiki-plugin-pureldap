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
#      - complexity=off + min-pwd-length=1 lets provision.py create
#        the `vagrant`/`vagrant` admin account that mirrors
#        splitbrain/vagrant-active-directory.
#   3. Install the TLS cert produced by the tls-init service.
#      The cert covers localhost / 127.0.0.1 / dc1.example.local so
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
            --complexity=off --min-pwd-length=1 \
            >/dev/null 2>&1; then
        break
    fi
    sleep 2
done
PWSETTINGS=$(samba-tool domain passwordsettings show)
if ! grep -q "Maximum password age (days): 42" <<<"$PWSETTINGS" \
        || ! grep -q "Minimum password age (days): 0" <<<"$PWSETTINGS" \
        || ! grep -q "Password history length: 0" <<<"$PWSETTINGS" \
        || ! grep -q "Password complexity: off" <<<"$PWSETTINGS"; then
    echo "[samba/setup] domain passwordsettings never accepted within 120s" >&2
    samba-tool domain passwordsettings set \
        --max-pwd-age=42 --min-pwd-age=0 --history-length=0 \
        --complexity=off --min-pwd-length=1 || true
    exit 1
fi

echo "[samba/setup] installing TLS cert from /certs..."
TLS_DIR=/var/lib/samba/private/tls
mkdir -p "$TLS_DIR"
cp /certs/cert.pem "$TLS_DIR/cert.pem"
cp /certs/key.pem  "$TLS_DIR/key.pem"
cp /certs/ca.pem   "$TLS_DIR/ca.pem"
chmod 600 "$TLS_DIR/key.pem"

# Tell samba to re-read its TLS cert. The previous incarnation of this
# script used `pkill -HUP samba`, but samba 4 treats SIGHUP as a fatal
# signal: the child exits, supervisord (which has no restart policy
# configured for this image) exits too, and the whole container dies
# with code 129 (= 128 + SIGHUP). Going through supervisorctl is the
# only safe way to bounce just the samba program in this image.
echo "[samba/setup] restarting samba via supervisorctl..."
supervisorctl restart samba >/dev/null
for i in $(seq 1 60); do
    if samba-tool user list >/dev/null 2>&1; then break; fi
    sleep 2
done
if ! samba-tool user list >/dev/null 2>&1; then
    echo "[samba/setup] samba-tool never came back after restart" >&2
    exit 1
fi

echo "[samba/setup] done."
