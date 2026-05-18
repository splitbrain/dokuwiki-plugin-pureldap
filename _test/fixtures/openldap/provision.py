#!/usr/bin/env python3
"""Apply users.csv + groups.csv to the OpenLDAP fixture.

Runs inside pureldap-openldap via the compose post_start hook, after
setup.sh has installed ldap-utils and seeded the ou=People / ou=Groups
containers.

Idempotent: if uid=a.legrand already exists, exits cleanly without
touching anything.

Drops /tmp/provisioned on success so the compose healthcheck flips
green.
"""

import csv
import subprocess
import sys
from pathlib import Path

FIXTURES = Path(__file__).resolve().parent.parent
USERS_CSV = FIXTURES / "users.csv"
GROUPS_CSV = FIXTURES / "groups.csv"

ADMIN_DN  = "cn=admin,dc=example,dc=com"
ADMIN_PW  = "Foo_b_ar123!"
BASE      = "dc=example,dc=com"
PEOPLE_OU = f"ou=People,{BASE}"
GROUPS_OU = f"ou=Groups,{BASE}"

USER_PASSWORD = "Foo_b_ar123!"
SENTINEL = Path("/tmp/provisioned")


def ldap(cmd, stdin=None, allow_exists=False):
    full = [cmd, "-x", "-H", "ldap://localhost",
            "-D", ADMIN_DN, "-w", ADMIN_PW]
    r = subprocess.run(full, input=stdin, text=True, capture_output=True)
    if r.returncode != 0:
        # err=68 (entryAlreadyExists) on ldapadd, err=20 (typeOrValueExists)
        # on ldapmodify with `add: memberUid`. Both mean "retry-safe noop".
        combined = (r.stdout or "") + (r.stderr or "")
        if allow_exists and (
            "Already exists" in combined
            or "already exists" in combined
            or "Type or value exists" in combined
        ):
            return
        sys.stderr.write(f"\n{full} failed (exit {r.returncode})\n")
        if stdin:    sys.stderr.write(f"stdin:\n{stdin}\n")
        if r.stdout: sys.stderr.write(f"stdout: {r.stdout}\n")
        if r.stderr: sys.stderr.write(f"stderr: {r.stderr}\n")
        sys.exit(1)


def entry_exists(dn):
    r = subprocess.run(
        ["ldapsearch", "-x", "-H", "ldap://localhost",
         "-D", ADMIN_DN, "-w", ADMIN_PW,
         "-b", dn, "-s", "base", "-LLL", "(objectClass=*)", "dn"],
        capture_output=True, text=True
    )
    return r.returncode == 0


def slappasswd(plain):
    # {SSHA} so slapd can verify it; deterministic? No — slappasswd
    # uses a random salt. The hash isn't reproducible, but the
    # provisioner runs once per container lifetime so that's fine.
    r = subprocess.run(["slappasswd", "-h", "{SSHA}", "-s", plain],
                       capture_output=True, text=True, check=True)
    return r.stdout.strip()


def derive_uid(first, last):
    # importusers.ps1 convention: lowercase(first[0].last)
    return (first[0] + "." + last).lower()


def add_group(name, gid):
    print(f"  + group {name}")
    ldif = (
        f"dn: cn={name},{GROUPS_OU}\n"
        f"objectClass: posixGroup\n"
        f"cn: {name}\n"
        f"gidNumber: {gid}\n"
    )
    ldap("ldapadd", stdin=ldif, allow_exists=True)


def add_user(uid, row, uid_number):
    cn = f"{row['first']} {row['last']}"
    pw_hash = slappasswd(USER_PASSWORD)
    lines = [
        f"dn: uid={uid},{PEOPLE_OU}",
        "objectClass: inetOrgPerson",
        "objectClass: organizationalPerson",
        "objectClass: posixAccount",
    ]
    if row.get("homepage"):
        lines.append("objectClass: labeledURIObject")
    # `c` (countryName) isn't allowed by inetOrgPerson/organizationalPerson —
    # add extensibleObject so the schema accepts it.
    if row.get("country"):
        lines.append("objectClass: extensibleObject")
    lines.extend([
        f"uid: {uid}",
        f"cn: {cn}",
        f"sn: {row['last']}",
        f"givenName: {row['first']}",
        f"displayName: {cn}",
        f"mail: {uid}@example.com",
        f"uidNumber: {uid_number}",
        f"gidNumber: {uid_number}",
        f"homeDirectory: /home/{uid}",
        f"userPassword: {pw_hash}",
    ])
    for col, attr in [
        ("phone",       "telephoneNumber"),
        ("mobile",      "mobile"),
        ("country",     "c"),
        ("city",        "l"),
        ("postal_code", "postalCode"),
        ("company",     "o"),
        ("street",      "street"),
        ("title",       "title"),
        ("department",  "departmentNumber"),
        ("homepage",    "labeledURI"),
    ]:
        v = row.get(col)
        if v:
            lines.append(f"{attr}: {v}")
    ldif = "\n".join(lines) + "\n"
    ldap("ldapadd", stdin=ldif, allow_exists=True)


def add_to_group(uid, group):
    ldap("ldapmodify", stdin=(
        f"dn: cn={group},{GROUPS_OU}\n"
        "changetype: modify\n"
        "add: memberUid\n"
        f"memberUid: {uid}\n"
    ), allow_exists=True)


def main():
    if entry_exists(f"uid=a.legrand,{PEOPLE_OU}"):
        print("[openldap/provision] already provisioned, skipping")
        SENTINEL.touch()
        return

    print("[openldap/provision] reading", GROUPS_CSV)
    groups = []
    with open(GROUPS_CSV) as f:
        for row in csv.DictReader(f):
            groups.append(row["name"])
    # Pre-create all groups (parent column ignored — posixGroup is flat).
    gid = 5000
    for name in groups:
        gid += 1
        add_group(name, gid)

    print("[openldap/provision] reading", USERS_CSV)
    uid_number = 1000
    with open(USERS_CSV) as f:
        rows = list(csv.DictReader(f))

    seen_uids = set()
    for row in rows:
        uid = derive_uid(row["first"], row["last"])
        if uid in seen_uids:
            print(f"  ! duplicate uid {uid}, skipping", file=sys.stderr)
            continue
        seen_uids.add(uid)
        uid_number += 1
        print(f"  + user {uid}")
        add_user(uid, row, uid_number)
        user_groups = []
        for col in ("group1", "group2", "group3"):
            grp = row.get(col, "").strip()
            if grp and grp not in user_groups:
                user_groups.append(grp)
        for grp in user_groups:
            add_to_group(uid, grp)
        if uid_number % 50 == 0:
            print(f"    ...{uid_number - 1000}/{len(rows)}")

    # Hardcoded long-name edge case (importusers.ps1's "Very Long" / longlong).
    print("  + user averylongusernamethatisverylong (longlong edge case)")
    long_uid = "averylongusernamethatisverylong"
    uid_number += 1
    pw_hash = slappasswd(USER_PASSWORD)
    ldap("ldapadd", stdin=(
        f"dn: uid={long_uid},{PEOPLE_OU}\n"
        "objectClass: inetOrgPerson\n"
        "objectClass: organizationalPerson\n"
        "objectClass: posixAccount\n"
        f"uid: {long_uid}\n"
        f"cn: Very Long\n"
        f"sn: Long\n"
        f"givenName: Very\n"
        f"displayName: Very Long\n"
        f"mail: {long_uid}@example.com\n"
        f"uidNumber: {uid_number}\n"
        f"gidNumber: {uid_number}\n"
        f"homeDirectory: /home/{long_uid}\n"
        f"userPassword: {pw_hash}\n"
    ))

    SENTINEL.touch()
    print("[openldap/provision] done")


if __name__ == "__main__":
    main()
