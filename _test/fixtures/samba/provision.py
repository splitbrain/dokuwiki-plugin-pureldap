#!/usr/bin/env python3
"""Apply users.csv + groups.csv to the Samba AD-DC fixture.

Runs inside pureldap-samba via the compose post_start hook, after
setup.sh has waited for samba-tool, set the password policy, and
installed the TLS cert.

Idempotent: if 'a.legrand' already exists, exits cleanly. Drops
/tmp/provisioned on success so the compose healthcheck flips green.
"""

import csv
import subprocess
import sys
from pathlib import Path

FIXTURES = Path(__file__).resolve().parent.parent
USERS_CSV = FIXTURES / "users.csv"
GROUPS_CSV = FIXTURES / "groups.csv"

USER_PASSWORD = "Foo_b_ar123!"
USERS_DN  = "CN=Users,DC=example,DC=com"
SAM_LDB   = "/var/lib/samba/private/sam.ldb"
SENTINEL  = Path("/tmp/provisioned")


def run(cmd, stdin=None, allow_exists=False):
    r = subprocess.run(cmd, input=stdin, text=True, capture_output=True)
    if r.returncode != 0:
        combined = (r.stdout or "") + (r.stderr or "")
        if allow_exists and "already exists" in combined:
            return
        sys.stderr.write(f"\n{cmd} failed (exit {r.returncode})\n")
        if stdin:    sys.stderr.write(f"stdin:\n{stdin}\n")
        if r.stdout: sys.stderr.write(f"stdout: {r.stdout}\n")
        if r.stderr: sys.stderr.write(f"stderr: {r.stderr}\n")
        sys.exit(1)


def derive_uid(first, last):
    return (first[0] + "." + last).lower()


def ldb_modify(dn, attrs):
    parts = [f"dn: {dn}", "changetype: modify"]
    sep_needed = False
    for name, value in attrs.items():
        if sep_needed:
            parts.append("-")
        parts.append(f"replace: {name}")
        parts.append(f"{name}: {value}")
        sep_needed = True
    ldif = "\n".join(parts) + "\n"
    run(["ldbmodify", "-i", "-H", SAM_LDB], stdin=ldif)


def user_exists(uid):
    r = subprocess.run(["samba-tool", "user", "show", uid],
                       capture_output=True, text=True)
    return r.returncode == 0


def add_group(name):
    print(f"  + group {name}")
    run(["samba-tool", "group", "add", name], allow_exists=True)


def add_user(uid, row):
    cn = f"{row['first']} {row['last']}"
    cmd = [
        "samba-tool", "user", "create", uid, USER_PASSWORD,
        f"--given-name={row['first']}",
        f"--surname={row['last']}",
        f"--mail-address={uid}@example.com",
    ]
    for col, flag in [
        ("phone",       "--telephone-number"),
        ("company",     "--company"),
        ("department",  "--department"),
    ]:
        v = row.get(col)
        if v:
            cmd.append(f"{flag}={v}")
    run(cmd)

    # samba-tool exposes a subset of AD attributes as flags; everything
    # else gets a post-create ldbmodify pass.
    attrs = {"displayName": cn}
    # 512 NORMAL_ACCOUNT | 65536 DONT_EXPIRE_PASSWD = 66048
    attrs["userAccountControl"] = "66048"
    attrs["userPrincipalName"] = f"{uid}@example.com"
    if row.get("mobile"):      attrs["mobile"]      = row["mobile"]
    if row.get("title"):       attrs["personalTitle"] = row["title"]
    if row.get("homepage"):    attrs["wWWHomePage"] = row["homepage"]
    if row.get("country"):     attrs["c"]           = row["country"]
    if row.get("city"):        attrs["l"]           = row["city"]
    if row.get("postal_code"): attrs["postalCode"]  = row["postal_code"]
    if row.get("street"):      attrs["streetAddress"] = row["street"]
    ldb_modify(f"CN={cn},{USERS_DN}", attrs)


def add_to_group(uid, group):
    run(["samba-tool", "group", "addmembers", group, uid], allow_exists=True)


def main():
    # No early-return idempotency: a previous run might have crashed
    # partway through, so we always walk the full list. Each step is
    # already idempotent (per-record user_exists checks + allow_exists
    # on group adds and group-member adds).
    print("[samba/provision] reading", GROUPS_CSV)
    group_rows = []
    with open(GROUPS_CSV) as f:
        for row in csv.DictReader(f):
            group_rows.append(row)
    for row in group_rows:
        add_group(row["name"])
    # Nested groups (`parent` column) in a second pass so the parent
    # exists before we try to put a member into it.
    for row in group_rows:
        parent = row.get("parent", "").strip()
        if parent:
            print(f"  + nest {row['name']} into {parent}")
            run(["samba-tool", "group", "addmembers", parent, row["name"]],
                allow_exists=True)

    print("[samba/provision] reading", USERS_CSV)
    with open(USERS_CSV) as f:
        rows = list(csv.DictReader(f))

    seen_uids = set()
    for i, row in enumerate(rows, 1):
        uid = derive_uid(row["first"], row["last"])
        if uid in seen_uids:
            print(f"  ! duplicate uid {uid}, skipping", file=sys.stderr)
            continue
        seen_uids.add(uid)
        if user_exists(uid):
            print(f"  = user {uid} already exists, skipping")
        else:
            print(f"  + user {uid}")
            add_user(uid, row)
        user_groups = []
        for col in ("group1", "group2", "group3"):
            grp = row.get(col, "").strip()
            if grp and grp not in user_groups:
                user_groups.append(grp)
        for grp in user_groups:
            add_to_group(uid, grp)
        if i % 50 == 0:
            print(f"    ...{i}/{len(rows)}")

    # Hardcoded long-name edge case (importusers.ps1's "Very Long" / longlong).
    if user_exists("longlong"):
        print("  = user longlong already exists, skipping")
    else:
        print("  + user longlong (averylongusernamethatisverylong UPN)")
        run([
            "samba-tool", "user", "create", "longlong", USER_PASSWORD,
            "--given-name=Very", "--surname=Long",
            "--mail-address=longlong@example.com",
        ])
        ldb_modify(f"CN=Very Long,{USERS_DN}", {
            "displayName":        "Very Long",
            "userAccountControl": "66048",
            "userPrincipalName":  "averylongusernamethatisverylong@example.com",
        })

    SENTINEL.touch()
    print("[samba/provision] done")


if __name__ == "__main__":
    main()
