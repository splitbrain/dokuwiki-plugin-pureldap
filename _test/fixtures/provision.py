#!/usr/bin/env python3
"""Apply users.json to one LDAP backend.

Runs INSIDE the matching LDAP container via the compose post_start
lifecycle hook (see _test/docker-compose.yml). The same script handles
both backends; pick which one with --backend.

Three classes:
    Provisioner          - abstract base, driver loop and shared helpers
    OpenLDAPProvisioner  - implements per-entity ops via ldapadd / ldapmodify
    SambaProvisioner     - implements them via samba-tool / ldbmodify

users.json is pure data: no per-backend tags, no connection info, no
conditions. Each subclass reads its own connection settings from
environment variables (set on the matching service in docker-compose.yml).

Both run() invocations are idempotent: each backend probes for the
canonical 'alice' entry and short-circuits if she's already there. On
success a sentinel file (/tmp/provisioned) is touched, which the
service's compose-level healthcheck reads — so `docker compose up
--wait` blocks until provisioning is actually done.
"""

import argparse
import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from abc import ABC, abstractmethod
from pathlib import Path

SPEC_PATH = Path(__file__).parent / "users.json"
SENTINEL = Path("/tmp/provisioned")


class Provisioner(ABC):
    def __init__(self, spec):
        self.spec = spec

    def run(self):
        name = type(self).__name__
        self.wait_until_ready()
        if self.is_already_provisioned():
            print(f"[{name}] already provisioned, skipping", flush=True)
            SENTINEL.touch()
            return
        print(f"[{name}] provisioning...", flush=True)

        self.ensure_root()
        self.apply_password_policy()
        for g in self.spec["groups"]:
            self.add_group(g)
        for g in self.spec["groups"]:
            for inner in g.get("contains", []):
                self.add_group_to_group(g["name"], inner)
        for u in self.spec["users"]:
            self.add_user(u)
        for u in self.spec["users"]:
            for grp in u.get("memberOf", []):
                self.add_user_to_group(u["uid"], grp)
        if "padding" in self.spec:
            self.add_padding_users(self.spec["padding"])
        self.finalize()
        SENTINEL.touch()
        print(f"[{name}] done", flush=True)

    @abstractmethod
    def wait_until_ready(self): ...
    @abstractmethod
    def is_already_provisioned(self): ...
    @abstractmethod
    def ensure_root(self): ...
    @abstractmethod
    def apply_password_policy(self): ...
    @abstractmethod
    def add_group(self, g): ...
    @abstractmethod
    def add_user(self, u): ...
    @abstractmethod
    def add_user_to_group(self, uid, group): ...
    @abstractmethod
    def add_group_to_group(self, outer, inner): ...
    @abstractmethod
    def add_padding_users(self, padding): ...
    @abstractmethod
    def finalize(self): ...

    @staticmethod
    def env(key):
        v = os.environ.get(key)
        if not v:
            raise RuntimeError(f"Missing required env var: {key}")
        return v

    @staticmethod
    def run_cmd(cmd, stdin=None, allow_fail=False):
        r = subprocess.run(cmd, input=stdin, text=True, capture_output=True)
        if r.returncode != 0 and not allow_fail:
            sys.stderr.write(f"\nCommand failed (exit {r.returncode}): {cmd}\n")
            if stdin is not None:
                sys.stderr.write(f"stdin:\n{stdin}\n")
            if r.stdout:
                sys.stderr.write(f"stdout:\n{r.stdout}\n")
            if r.stderr:
                sys.stderr.write(f"stderr:\n{r.stderr}\n")
            sys.exit(1)
        return r


class OpenLDAPProvisioner(Provisioner):
    def __init__(self, spec):
        super().__init__(spec)
        self.host = self.env("PROVISION_HOST")
        self.port = int(self.env("PROVISION_PORT"))
        self.bind_dn = self.env("PROVISION_BIND_DN")
        self.bind_pw = self.env("PROVISION_BIND_PW")
        self.base = self.env("PROVISION_BASE")
        self.people_ou = self.env("PROVISION_PEOPLE_OU")
        self.groups_ou = self.env("PROVISION_GROUPS_OU")
        self.next_uid = 1000
        self.next_gid = 5000
        self._ensure_ldap_utils()

    def _ensure_ldap_utils(self):
        # osixia/openldap doesn't always ship ldap-utils. Install on
        # demand so we have ldapsearch / ldapadd / ldapmodify available.
        if shutil.which("ldapadd"):
            return
        print("Installing ldap-utils...", flush=True)
        env = {**os.environ, "DEBIAN_FRONTEND": "noninteractive"}
        subprocess.run(["apt-get", "update", "-qq"], check=True, env=env)
        subprocess.run(["apt-get", "install", "-y", "-qq", "ldap-utils"],
                       check=True, env=env)

    def wait_until_ready(self):
        print("[OpenLDAPProvisioner] waiting for slapd...", flush=True)
        deadline = time.time() + 120
        while time.time() < deadline:
            if self._entry_exists(self.base):
                return
            time.sleep(0.5)
        raise RuntimeError("slapd did not become responsive within 120s")

    def is_already_provisioned(self):
        return self._entry_exists(f"uid=alice,{self.people_ou}")

    def ensure_root(self):
        for dn in (self.people_ou, self.groups_ou):
            if self._entry_exists(dn):
                continue
            rdn_attr, rdn_val = dn.split(',', 1)[0].split('=', 1)
            self._ldap_add(
                f"dn: {dn}\n"
                f"objectClass: organizationalUnit\n"
                f"{rdn_attr}: {rdn_val}\n"
            )

    def apply_password_policy(self):
        pass  # not modelled for slapd in this fixture

    def add_group(self, g):
        self.next_gid += 1
        print(f"  + group {g['name']}", flush=True)
        self._ldap_add(
            f"dn: cn={g['name']},{self.groups_ou}\n"
            f"objectClass: posixGroup\n"
            f"cn: {g['name']}\n"
            f"gidNumber: {self.next_gid}\n"
        )

    def add_user(self, u):
        self.next_uid += 1
        cn = f"{u['givenName']} {u['sn']}"
        ldif = (
            f"dn: uid={u['uid']},{self.people_ou}\n"
            f"objectClass: inetOrgPerson\n"
            f"objectClass: posixAccount\n"
            f"uid: {u['uid']}\n"
            f"cn: {cn}\n"
            f"sn: {u['sn']}\n"
            f"givenName: {u['givenName']}\n"
        )
        if "mail" in u:
            ldif += f"mail: {u['mail']}\n"
        if "mobile" in u:
            ldif += f"mobile: {u['mobile']}\n"
        ldif += (
            f"uidNumber: {self.next_uid}\n"
            f"gidNumber: {self.next_uid}\n"
            f"homeDirectory: /home/{u['uid']}\n"
            f"userPassword: {_ssha(u['password'])}\n"
        )
        print(f"  + user {u['uid']}", flush=True)
        self._ldap_add(ldif)

    def add_user_to_group(self, uid, group):
        self._ldap_modify(
            f"dn: cn={group},{self.groups_ou}\n"
            f"changetype: modify\n"
            f"add: memberUid\n"
            f"memberUid: {uid}\n"
        )

    def add_group_to_group(self, outer, inner):
        # posixGroup uses memberUid (RFC 2307) and has no nesting concept.
        # The spec carries 'contains' for AD's sake; on slapd it's a no-op.
        pass

    def add_padding_users(self, p):
        print(f"  + padding users (1..{p['count']})", flush=True)
        for i in range(1, p["count"] + 1):
            uid = p["uid_format"] % i
            given = p["givenName_format"] % i
            self.next_uid += 1
            self._ldap_add(
                f"dn: uid={uid},{self.people_ou}\n"
                f"objectClass: inetOrgPerson\n"
                f"objectClass: posixAccount\n"
                f"uid: {uid}\n"
                f"cn: {given} {p['sn']}\n"
                f"sn: {p['sn']}\n"
                f"givenName: {given}\n"
                f"uidNumber: {self.next_uid}\n"
                f"gidNumber: {self.next_uid}\n"
                f"homeDirectory: /home/{uid}\n"
                f"userPassword: {_ssha(p['password'])}\n"
            )
            for m in p.get("memberships", []):
                if i <= m["first_n"]:
                    self.add_user_to_group(uid, m["group"])
            if i % 50 == 0:
                print(f"    ...{i}/{p['count']}", flush=True)

    def finalize(self):
        pass

    def _entry_exists(self, dn):
        r = self.run_cmd([
            "ldapsearch", "-x",
            "-H", f"ldap://{self.host}:{self.port}",
            "-D", self.bind_dn, "-w", self.bind_pw,
            "-b", dn, "-s", "base", "-LLL", "(objectClass=*)", "dn",
        ], allow_fail=True)
        return r.returncode == 0

    def _ldap_add(self, ldif):
        self.run_cmd([
            "ldapadd", "-x",
            "-H", f"ldap://{self.host}:{self.port}",
            "-D", self.bind_dn, "-w", self.bind_pw,
        ], stdin=ldif)

    def _ldap_modify(self, ldif):
        self.run_cmd([
            "ldapmodify", "-x",
            "-H", f"ldap://{self.host}:{self.port}",
            "-D", self.bind_dn, "-w", self.bind_pw,
        ], stdin=ldif)


class SambaProvisioner(Provisioner):
    SAM_LDB = "/var/lib/samba/private/sam.ldb"
    TLS_DIR = "/var/lib/samba/private/tls"

    def __init__(self, spec):
        super().__init__(spec)
        self.users_dn = self.env("PROVISION_USERS_DN")

    def wait_until_ready(self):
        # samba-tool only responds once the AD-DC has finished its
        # own first-boot domain provisioning. That takes 30-90s.
        print("[SambaProvisioner] waiting for samba-tool (slow first boot)...",
              flush=True)
        deadline = time.time() + 300
        while time.time() < deadline:
            r = subprocess.run(["samba-tool", "user", "list"],
                               stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)
            if r.returncode == 0:
                return
            time.sleep(2)
        raise RuntimeError("samba did not become responsive within 300s")

    def is_already_provisioned(self):
        r = subprocess.run(["samba-tool", "user", "show", "alice"],
                           stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
        return r.returncode == 0

    def ensure_root(self):
        pass  # CN=Users,DC=… is created by samba's first-boot provisioning

    def apply_password_policy(self):
        days = self.spec.get("password_policy", {}).get("max_pwd_age_days")
        if days is None:
            return
        self.run_cmd([
            "samba-tool", "domain", "passwordsettings", "set",
            f"--max-pwd-age={days}",
        ])

    def add_group(self, g):
        print(f"  + group {g['name']}", flush=True)
        self.run_cmd(["samba-tool", "group", "add", g["name"]])

    def add_user(self, u):
        print(f"  + user {u['uid']}", flush=True)
        cmd = [
            "samba-tool", "user", "create", u["uid"], u["password"],
            f"--given-name={u['givenName']}",
            f"--surname={u['sn']}",
            "--use-username-as-cn",
        ]
        if "mail" in u:
            cmd.append(f"--mail-address={u['mail']}")
        self.run_cmd(cmd)

        attrs = {"displayName": f"{u['givenName']} {u['sn']}"}
        if "mobile" in u:
            attrs["mobile"] = u["mobile"]
        if u.get("passwordNeverExpires"):
            # NORMAL_ACCOUNT 512 | DONT_EXPIRE_PASSWD 65536 = 66048
            attrs["userAccountControl"] = "66048"
        self._ldb_modify(f"CN={u['uid']},{self.users_dn}", attrs)

    def add_user_to_group(self, uid, group):
        self.run_cmd(["samba-tool", "group", "addmembers", group, uid])

    def add_group_to_group(self, outer, inner):
        self.run_cmd(["samba-tool", "group", "addmembers", outer, inner])

    def add_padding_users(self, p):
        print(f"  + padding users (1..{p['count']})", flush=True)
        for i in range(1, p["count"] + 1):
            uid = p["uid_format"] % i
            given = p["givenName_format"] % i
            self.run_cmd([
                "samba-tool", "user", "create", uid, p["password"],
                f"--given-name={given}",
                f"--surname={p['sn']}",
                "--use-username-as-cn",
            ])
            for m in p.get("memberships", []):
                if i <= m["first_n"]:
                    self.run_cmd([
                        "samba-tool", "group", "addmembers",
                        m["group"], uid,
                    ])
            if i % 50 == 0:
                print(f"    ...{i}/{p['count']}", flush=True)

    def finalize(self):
        # Samba's auto-generated TLS cert is issued for the DC's FQDN
        # (dc1.example.local). The plugin connects to localhost:7389
        # with STARTTLS — FreeDSx's hostname check rejects the handshake
        # even with validate=self. Reissue with a subjectAltName covering
        # localhost and 127.0.0.1, then HUP samba so it reloads.
        print("  + regenerate TLS cert with localhost SAN", flush=True)
        os.makedirs(self.TLS_DIR, exist_ok=True)
        self.run_cmd([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", f"{self.TLS_DIR}/key.pem",
            "-out", f"{self.TLS_DIR}/cert.pem",
            "-days", "365",
            "-subj", "/CN=localhost",
            "-addext", "subjectAltName=DNS:localhost,DNS:dc1.example.local,IP:127.0.0.1",
        ])
        shutil.copy(f"{self.TLS_DIR}/cert.pem", f"{self.TLS_DIR}/ca.pem")
        os.chmod(f"{self.TLS_DIR}/key.pem", 0o600)
        subprocess.run(["pkill", "-HUP", "samba"], check=False)

    def _ldb_modify(self, dn, attrs):
        parts = [f"dn: {dn}\nchangetype: modify\n"]
        sep = ""
        for name, value in attrs.items():
            parts.append(f"{sep}replace: {name}\n{name}: {value}\n")
            sep = "-\n"
        self.run_cmd(["ldbmodify", "-H", self.SAM_LDB], stdin="".join(parts))


def _ssha(pw):
    # Deterministic salt so the LDIF is reproducible across runs.
    salt = hashlib.sha1(f"ssha-salt:{pw}".encode()).digest()[:4]
    h = hashlib.sha1(pw.encode() + salt).digest()
    return "{SSHA}" + base64.b64encode(h + salt).decode()


def _strip_comments(v):
    if isinstance(v, dict):
        return {k: _strip_comments(vv) for k, vv in v.items()
                if not (isinstance(k, str) and k.startswith("_comment"))}
    if isinstance(v, list):
        return [_strip_comments(x) for x in v]
    return v


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--backend", required=True, choices=["openldap", "samba"])
    args = p.parse_args()

    with open(SPEC_PATH) as f:
        spec = _strip_comments(json.load(f))

    cls = {
        "openldap": OpenLDAPProvisioner,
        "samba": SambaProvisioner,
    }[args.backend]
    cls(spec).run()


if __name__ == "__main__":
    main()
