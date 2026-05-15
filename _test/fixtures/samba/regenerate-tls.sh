#!/bin/bash
# Regenerate Samba's TLS cert so it includes 'localhost' / 127.0.0.1 in
# the subjectAltName. Without this, pureldap (FreeDSx) refuses the
# STARTTLS handshake when the test config connects to localhost:7389 —
# even with validate=self enabled — because the cert Samba ships defaults
# to CN=dc1.example.local only.

set -euo pipefail

TLS_DIR="/var/lib/samba/private/tls"
mkdir -p "$TLS_DIR"

openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$TLS_DIR/key.pem" \
    -out "$TLS_DIR/cert.pem" \
    -days 365 \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,DNS:dc1.example.local,IP:127.0.0.1" \
    2>/dev/null

# Self-signed: copy cert as the CA file too so clients that want a chain
# get something coherent.
cp "$TLS_DIR/cert.pem" "$TLS_DIR/ca.pem"
chmod 600 "$TLS_DIR/key.pem"

# Tell samba to reread the cert. On nowsci/samba-domain the easiest path
# is to restart the samba process (PID 1 is supervised by /init.sh).
pkill -HUP samba || true
