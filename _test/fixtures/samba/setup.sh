#!/usr/bin/env bash
# Invoked once by the workflow (or by hand) via `docker exec` once the
# samba container is up. Waits for first-boot domain provisioning to
# finish (samba-tool returns 0), sets the password-age policy explicitly
# so testMaxPasswordAge can't drift, and installs the shared TLS material
# from the tls-init volume mounted read-only at /certs.
set -euo pipefail

TLS_SRC="/certs"
TLS_DST="/var/lib/samba/private/tls"

echo "[samba setup] waiting for samba-tool..."
for _ in $(seq 1 150); do
    if samba-tool user list >/dev/null 2>&1; then
        break
    fi
    sleep 2
done

if ! samba-tool user list >/dev/null 2>&1; then
    echo "[samba setup] samba-tool never became responsive" >&2
    exit 1
fi

echo "[samba setup] setting max-pwd-age=42"
samba-tool domain passwordsettings set --max-pwd-age=42

echo "[samba setup] installing TLS cert from ${TLS_SRC}"
install -d -m 755 "${TLS_DST}"
install -m 644 "${TLS_SRC}/cert.pem" "${TLS_DST}/cert.pem"
install -m 644 "${TLS_SRC}/ca.pem"   "${TLS_DST}/ca.pem"
install -m 600 "${TLS_SRC}/key.pem"  "${TLS_DST}/key.pem"

# HUP samba to reload TLS material. Best-effort — if no process matches
# (e.g. on the very first start before samba is up), the provisioner's
# later activity will exercise the new cert anyway.
pkill -HUP samba 2>/dev/null || true

echo "[samba setup] done"
