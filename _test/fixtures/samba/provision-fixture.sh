#!/bin/bash
# Lifecycle wrapper around the auto-generated Samba provisioning data.
# Runs INSIDE the pureldap-samba container.
#
# 1. wait for samba-tool to become responsive (domain provisioning
#    only finishes well after the entrypoint hands off)
# 2. apply password policy from the shared spec
# 3. source provision-data.sh — the generated user/group/membership
#    calls rendered from people.json by _test/fixtures/regenerate.sh
# 4. regenerate the TLS cert with a localhost SAN so the test client
#    (FreeDSx with validate=self) can complete the STARTTLS handshake
# 5. mark the fixture provisioned so re-running this script is a no-op

set -euo pipefail

if [ -f /var/lib/samba/.pureldap-provisioned ]; then
    echo "Fixture already provisioned."
    exit 0
fi

echo "Waiting for samba to accept ldap queries..."
for i in $(seq 1 60); do
    if samba-tool user list >/dev/null 2>&1; then
        echo "Samba ready after ${i}s"
        break
    fi
    sleep 1
done

# 42-day max password age — testMaxPasswordAge asserts exactly this.
# Driven by password_policy.max_pwd_age_days in people.json.
samba-tool domain passwordsettings set --max-pwd-age=42

# Source the rendered user/group/membership commands.
# shellcheck source=/dev/null
source /provision-data.sh

# ----- TLS cert with localhost SAN -------------------------------------------
# Samba's default auto-generated cert is issued for the DC's FQDN
# (dc1.example.local). The pureldap test config connects to
# localhost:7389 with STARTTLS, so FreeDSx's hostname check rejects
# the handshake even with validate=self. Reissue a self-signed cert
# whose subjectAltName covers localhost and 127.0.0.1, then HUP samba
# so it reloads.
echo "Regenerating Samba TLS cert with localhost SAN..."
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

touch /var/lib/samba/.pureldap-provisioned
echo "Fixture provisioning complete."
