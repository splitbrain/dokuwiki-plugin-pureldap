#!/bin/bash
# Regenerate Samba's TLS cert with a localhost SAN so the test client
# (FreeDSx with validate=self) can complete the STARTTLS handshake.
# Runs INSIDE the pureldap-samba container, invoked from the host by
# SambaProvisioner::finalize() as the last step of fixture setup.
#
# Samba's default auto-generated cert is issued for the DC's FQDN
# (dc1.example.local); the plugin connects to localhost:7389, so we
# reissue with subjectAltName covering localhost and 127.0.0.1 and
# HUP samba to pick up the new cert.

set -euo pipefail

TLS_DIR=/var/lib/samba/private/tls
mkdir -p "$TLS_DIR"

openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$TLS_DIR/key.pem" \
    -out "$TLS_DIR/cert.pem" \
    -days 365 \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,DNS:dc1.example.local,IP:127.0.0.1" \
    2>/dev/null

cp "$TLS_DIR/cert.pem" "$TLS_DIR/ca.pem"
chmod 600 "$TLS_DIR/key.pem"
pkill -HUP samba || true
