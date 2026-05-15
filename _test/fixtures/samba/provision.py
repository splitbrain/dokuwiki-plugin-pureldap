#!/usr/bin/env python3
"""Apply users.csv + groups.csv to the Samba AD-DC container.

Driven by the compose post_start hook after setup.sh has installed
TLS material and set the password policy. Builds users via
samba-tool for the attributes that have CLI flags and an LDIF +
ldbmodify pass for the rest (mobile, wWWHomePage, personalTitle,
userAccountControl=66048 for never-expires).

Idempotent: probes samba-tool user show a.legrand and exits early
if the user is already there. Touches /tmp/provisioned on success.
"""

import csv
import subprocess
import sys
from pathlib import Path

DOMAIN = "example.com"
USERS_DN = "CN=Users,DC=example,DC=com"
PASSWORD = "Foo_b_ar123!"
SAM_LDB = "/var/lib/samba/private/sam.ldb"

FIXTURES = Path(__file__).resolve().parent.parent
USERS_CSV = FIXTURES / "users.csv"
GROUPS_CSV = FIXTURES / "groups.csv"
SENTINEL = Path("/tmp/provisioned")


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


def user_exists(uid):
    return run(["samba-tool", "user", "show", uid], check=False).returncode == 0


def group_exists(name):
    return run(["samba-tool", "group", "show", name], check=False).returncode == 0


def uid_of(first, last):
    return f"{first[:1]}.{last}".lower()


def add_groups(group_rows):
    for g in group_rows:
        if group_exists(g["name"]):
            print(f"  = group {g['name']} (exists)", flush=True)
            continue
        print(f"  + group {g['name']}", flush=True)
        run(["samba-tool", "group", "add", g["name"]])

    for g in group_rows:
        parent = g.get("parent", "").strip()
        if not parent:
            continue
        # idempotent: 'addmembers' fails on duplicates, so ignore failure
        run(["samba-tool", "group", "addmembers", parent, g["name"]], check=False)


def create_user(uid, first, last, row, *, upn=None, mail=None):
    upn = upn or f"{uid}@example.com"
    mail = mail or f"{uid}@example.com"
    cmd = [
        "samba-tool", "user", "create", uid, PASSWORD,
        f"--given-name={first}",
        f"--surname={last}",
        f"--userprincipalname={upn}",
        f"--mail-address={mail}",
    ]
    if row:
        for csv_key, flag in [
            ("phone",       "--telephone-number"),
            ("city",        "--city"),
            ("company",     "--company"),
            ("department",  "--department"),
            ("postal_code", "--postal-code"),
            ("street",      "--street"),
        ]:
            val = row.get(csv_key, "").strip()
            if val:
                cmd.append(f"{flag}={val}")
    run(cmd)


def ldb_modify_user(uid, attrs):
    """Patch attributes samba-tool can't set on the new user."""
    dn = f"CN={attrs.pop('cn_for_dn')},{USERS_DN}"
    parts = [f"dn: {dn}\nchangetype: modify\n"]
    sep = ""
    for name, value in attrs.items():
        parts.append(f"{sep}replace: {name}\n{name}: {value}\n")
        sep = "-\n"
    run(["ldbmodify", "-H", SAM_LDB], stdin="".join(parts))


def patch_user(uid, first, last, row):
    """Set attributes samba-tool's user-create CLI doesn't cover."""
    attrs = {
        "cn_for_dn": f"{first} {last}",
        # never-expires: NORMAL_ACCOUNT (512) | DONT_EXPIRE_PASSWD (65536)
        "userAccountControl": "66048",
    }
    if row:
        for csv_key, attr in [
            ("mobile",   "mobile"),
            ("country",  "c"),
            ("title",    "personalTitle"),
            ("homepage", "wWWHomePage"),
        ]:
            val = row.get(csv_key, "").strip()
            if val:
                attrs[attr] = val
    ldb_modify_user(uid, attrs)


def add_user_to_group(uid, group):
    run(["samba-tool", "group", "addmembers", group, uid])


def provision_user(first, last, row):
    uid = uid_of(first, last)
    if user_exists(uid):
        print(f"  = user {uid} (exists)", flush=True)
        return
    print(f"  + user {uid}", flush=True)
    create_user(uid, first, last, row)
    patch_user(uid, first, last, row)
    for col in ("group1", "group2", "group3"):
        group = (row.get(col, "") if row else "").strip()
        if group:
            add_user_to_group(uid, group)


def main():
    if user_exists("a.legrand"):
        print("[samba] already provisioned, skipping", flush=True)
        SENTINEL.touch()
        return

    print("[samba] provisioning...", flush=True)

    with open(GROUPS_CSV, newline="") as f:
        group_rows = list(csv.DictReader(f))
    add_groups(group_rows)

    with open(USERS_CSV, newline="") as f:
        for row in csv.DictReader(f):
            provision_user(row["first"].strip(), row["last"].strip(), row)

    # The hardcoded long-name edge case from importusers.ps1: sAMAccountName
    # short, UserPrincipalName long.
    long_uid = "longlong"
    if not user_exists(long_uid):
        print(f"  + user {long_uid}", flush=True)
        create_user(
            long_uid, "Very", "Long", row=None,
            upn=f"averylongusernamethatisverylong@{DOMAIN}",
            mail=f"{long_uid}@example.com",
        )
        ldb_modify_user(long_uid, {
            "cn_for_dn": "Very Long",
            "userAccountControl": "66048",
        })

    SENTINEL.touch()
    print("[samba] done", flush=True)


if __name__ == "__main__":
    main()
