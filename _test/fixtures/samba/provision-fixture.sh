#!/bin/bash
# Provision the pureldap AD test fixture inside a running Samba AD-DC.
# Mirrors the relevant subset of splitbrain/vagrant-active-directory:
# the named users the tests reference, the alpha/beta/"gamma nested"
# group structure with beta containing "gamma nested" as a member, a
# 42-day password policy, and ~260 padding users so the count
# assertions (>250 in "Domain Users", 20-150 in alpha) pass.

set -euo pipefail

DOMAIN_DN="DC=example,DC=local"
ADMIN_PASS="${DOMAINPASS:-Vagrantvagrantvagrant1}"
USER_PASS='Foo_b_ar123!'

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
samba-tool domain passwordsettings set --max-pwd-age=42

# ----- helpers ---------------------------------------------------------------

create_user() {
    local sam="$1" given="$2" surname="$3" mail="$4"
    samba-tool user create "$sam" "$USER_PASS" \
        --given-name="$given" \
        --surname="$surname" \
        --mail-address="$mail" \
        --use-username-as-cn \
        >/dev/null
    # set displayName so ADClient::entry2User picks up the right "name"
    ldbmodify -H /var/lib/samba/private/sam.ldb >/dev/null <<EOF
dn: CN=${sam},CN=Users,${DOMAIN_DN}
changetype: modify
replace: displayName
displayName: ${given} ${surname}
EOF
}

set_attr() {
    local sam="$1" attr="$2" value="$3"
    ldbmodify -H /var/lib/samba/private/sam.ldb >/dev/null <<EOF
dn: CN=${sam},CN=Users,${DOMAIN_DN}
changetype: modify
replace: ${attr}
${attr}: ${value}
EOF
}

# ----- groups ----------------------------------------------------------------

samba-tool group add alpha           >/dev/null
samba-tool group add beta            >/dev/null
samba-tool group add "Gamma Nested"  >/dev/null
# nested membership: "Gamma Nested" is a member of beta
samba-tool group addmembers beta "Gamma Nested" >/dev/null

# ----- named users referenced by ADClientTest --------------------------------

create_user a.legrand   Amerigo  Legrand  a.legrand@example.com
set_attr    a.legrand   mobile   "+63 (483) 526-8809"
# ADClientTest::testGetUser asserts expires=false, which means the
# DONT_EXPIRE_PASSWD bit (0x10000) must be set in userAccountControl.
# 512 = NORMAL_ACCOUNT, 65536 = DONT_EXPIRE_PASSWD → 66048.
set_attr    a.legrand   userAccountControl 66048

create_user a.blaskett  Allene   Blaskett a.blaskett@example.com
create_user andras.k    Andras   Kovac    andras.k@example.com
create_user m.albro     Maire    Albro    m.albro@example.com
create_user m.mcnevin   Mike     McNevin  m.mcnevin@example.com
create_user x.guiu      Xanthus  Guiu     x.guiu@example.com
create_user averylongusernamethatisverylong Long Username long@example.com

# memberships expected by the assertions:
# - a.legrand:  beta + "Gamma Nested"  (groups returned = [beta, gamma nested, domain users, user])
# - m.albro:    "Gamma Nested"          (inherits beta when recursivegroups=1)
# - m.mcnevin:  "Gamma Nested"
# - a.blaskett: alpha
# - andras.k:   alpha                   (testGetFilteredUsers name=Andras STARTSWITH match)
samba-tool group addmembers alpha          a.blaskett,andras.k       >/dev/null
samba-tool group addmembers beta           a.legrand                 >/dev/null
samba-tool group addmembers "Gamma Nested" a.legrand,m.albro,m.mcnevin >/dev/null

# ----- padding users so count assertions pass --------------------------------
# Targets:
#   * Domain Users > 250  (everyone we create lands here automatically)
#   * alpha in [20, 150)
#
# alpha gets ~30 members, the rest are unaffiliated Domain Users.

echo "Creating padding users (this takes a minute)..."
for i in $(seq 1 260); do
    sam=$(printf "p.user%03d" "$i")
    samba-tool user create "$sam" "$USER_PASS" \
        --given-name="P${i}" \
        --surname="User" \
        --use-username-as-cn \
        >/dev/null
    if [ "$i" -le 28 ]; then
        samba-tool group addmembers alpha "$sam" >/dev/null
    fi
done

touch /var/lib/samba/.pureldap-provisioned
echo "Fixture provisioning complete."
