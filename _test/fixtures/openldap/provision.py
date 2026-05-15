#!/usr/bin/env python3
"""Apply users.csv + groups.csv to the OpenLDAP container.

Driven by the compose post_start hook after setup.sh has installed
ldap-utils and created the OUs. The same CSV files also feed the
samba provisioner — they're the upstream vagrant
(splitbrain/vagrant-active-directory) test data, used verbatim.

Idempotent: probes for uid=a.legrand and exits early if the data is
already there. On success touches /tmp/provisioned which the
compose healthcheck reads.
"""

import csv
import os
import subprocess
import sys
from pathlib import Path

HOST = "localhost"
PORT = "389"
BIND_DN = "cn=admin,dc=example,dc=com"
BIND_PW = "Foo_b_ar123!"
BASE = "dc=example,dc=com"
PEOPLE_OU = f"ou=People,{BASE}"
GROUPS_OU = f"ou=Groups,{BASE}"
PASSWORD = "Foo_b_ar123!"

FIXTURES = Path(__file__).resolve().parent.parent
USERS_CSV = FIXTURES / "users.csv"
GROUPS_CSV = FIXTURES / "groups.csv"
SENTINEL = Path("/tmp/provisioned")

LDAP_URI = f"ldap://{HOST}:{PORT}"


def run(cmd, stdin=None, check=True):
    r = subprocess.run(cmd, input=stdin, text=True, capture_output=True)
    if check and r.returncode != 0:
        sys.stderr.write(f"command failed (exit {r.returncode}): {cmd}\n")
        if stdin is not None:
            sys.stderr.write(f"--- stdin ---\n{stdin}\n")
        if r.stdout:
            sys.stderr.write(f"--- stdout ---\n{r.stdout}\n")
        if r.stderr:
            sys.stderr.write(f"--- stderr ---\n{r.stderr}\n")
        sys.exit(1)
    return r


def entry_exists(dn):
    r = run([
        "ldapsearch", "-x", "-H", LDAP_URI,
        "-D", BIND_DN, "-w", BIND_PW,
        "-b", dn, "-s", "base", "-LLL", "(objectClass=*)", "dn",
    ], check=False)
    return r.returncode == 0


def ldap_add(ldif):
    run([
        "ldapadd", "-x", "-H", LDAP_URI,
        "-D", BIND_DN, "-w", BIND_PW,
    ], stdin=ldif)


def ldap_modify(ldif):
    run([
        "ldapmodify", "-x", "-H", LDAP_URI,
        "-D", BIND_DN, "-w", BIND_PW,
    ], stdin=ldif)


def ssha(pw):
    r = run(["slappasswd", "-h", "{SSHA}", "-s", pw])
    return r.stdout.strip()


def uid_of(first, last):
    return f"{first[:1]}.{last}".lower()


def make_user_ldif(uid, first, last, mail, row, password_hash):
    cn = f"{first} {last}"
    classes = [
        "objectClass: top",
        "objectClass: person",
        "objectClass: organizationalPerson",
        "objectClass: inetOrgPerson",
        "objectClass: posixAccount",
    ]
    homepage = (row or {}).get("homepage", "").strip()
    if homepage:
        classes.append("objectClass: labeledURIObject")

    lines = [f"dn: uid={uid},{PEOPLE_OU}"]
    lines.extend(classes)
    lines.append(f"uid: {uid}")
    lines.append(f"cn: {cn}")
    lines.append(f"sn: {last}")
    lines.append(f"givenName: {first}")
    lines.append(f"displayName: {cn}")
    lines.append(f"mail: {mail}")

    optional = [
        ("phone",       "telephoneNumber"),
        ("mobile",      "mobile"),
        ("country",     "c"),
        ("city",        "l"),
        ("postal_code", "postalCode"),
        ("company",     "o"),
        ("street",      "street"),
        ("title",       "title"),
        ("department",  "departmentNumber"),
    ]
    if row:
        for csv_key, attr in optional:
            val = row.get(csv_key, "").strip()
            if val:
                lines.append(f"{attr}: {val}")
        if homepage:
            lines.append(f"labeledURI: {homepage}")

    # posixAccount required attributes
    lines.append("uidNumber: 0")
    lines.append("gidNumber: 0")
    lines.append(f"homeDirectory: /home/{uid}")
    lines.append(f"userPassword: {password_hash}")
    return "\n".join(lines) + "\n"


def add_groups(group_rows):
    for gid_offset, g in enumerate(group_rows):
        dn = f"cn={g['name']},{GROUPS_OU}"
        if entry_exists(dn):
            print(f"  = group {g['name']} (exists)", flush=True)
            continue
        print(f"  + group {g['name']}", flush=True)
        ldap_add(
            f"dn: {dn}\n"
            "objectClass: top\n"
            "objectClass: posixGroup\n"
            f"cn: {g['name']}\n"
            f"gidNumber: {5000 + gid_offset}\n"
        )


def add_user(uid, first, last, row, password_hash, uid_number):
    mail = f"{uid}@example.com"
    ldif = make_user_ldif(uid, first, last, mail, row, password_hash)
    # patch uidNumber/gidNumber to the actual sequence value
    ldif = ldif.replace("uidNumber: 0", f"uidNumber: {uid_number}", 1)
    ldif = ldif.replace("gidNumber: 0", f"gidNumber: {uid_number}", 1)
    ldap_add(ldif)


def add_membership(group, uid):
    ldap_modify(
        f"dn: cn={group},{GROUPS_OU}\n"
        "changetype: modify\n"
        "add: memberUid\n"
        f"memberUid: {uid}\n"
    )


def main():
    if entry_exists(f"uid=a.legrand,{PEOPLE_OU}"):
        print("[openldap] already provisioned, skipping", flush=True)
        SENTINEL.touch()
        return

    print("[openldap] provisioning...", flush=True)
    password_hash = ssha(PASSWORD)

    with open(GROUPS_CSV, newline="") as f:
        group_rows = list(csv.DictReader(f))
    add_groups(group_rows)

    next_uid_number = 1001
    with open(USERS_CSV, newline="") as f:
        for row in csv.DictReader(f):
            first = row["first"].strip()
            last = row["last"].strip()
            uid = uid_of(first, last)
            print(f"  + user {uid}", flush=True)
            add_user(uid, first, last, row, password_hash, next_uid_number)
            next_uid_number += 1
            for col in ("group1", "group2", "group3"):
                group = row.get(col, "").strip()
                if group:
                    add_membership(group, uid)

    # The hardcoded long-name user — mirrors the ps1's "Very Long".
    # OpenLDAP has no sAMAccountName / UPN, so the uid attribute itself
    # carries the long form. sn/givenName/mail follow the ps1.
    long_uid = "averylongusernamethatisverylong"
    print(f"  + user {long_uid}", flush=True)
    long_ldif = make_user_ldif(
        long_uid, "Very", "Long",
        "longlong@example.com",
        None,
        password_hash,
    )
    long_ldif = long_ldif.replace("uidNumber: 0", f"uidNumber: {next_uid_number}", 1)
    long_ldif = long_ldif.replace("gidNumber: 0", f"gidNumber: {next_uid_number}", 1)
    ldap_add(long_ldif)

    SENTINEL.touch()
    print("[openldap] done", flush=True)


if __name__ == "__main__":
    main()
