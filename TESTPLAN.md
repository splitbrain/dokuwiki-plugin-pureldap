# Simplify the integration-test fixtures

## Context

The current `_test/fixtures/` is heavier than the job needs:

- `provision.py` (~420 lines) embeds CSV-equivalent data, installs
  `ldap-utils` at runtime, regenerates TLS certs, sets AD password
  policy, creates OUs, and synthesises 260 padding users, all behind
  an `abc.ABC` + two subclass skeleton.
- `users.json` mixes data with `_comment` keys, has drifted from the
  original test data (`Xanthus Guiu` instead of `Xena Guiu`,
  `andras.k Kovac` instead of `Andras Clitsome`, etc.), and replaced
  the rich original schema with `p.user001/P1/User` filler.
- Test files and compose still reference "vagrant" branding from the
  old `vagrant-active-directory` fixture, including a literal admin
  user named `vagrant`.

The original
[`splitbrain/vagrant-active-directory/scripts/users.csv`](https://github.com/splitbrain/vagrant-active-directory/blob/master/scripts/users.csv)
plus its companion
[`importusers.ps1`](https://github.com/splitbrain/vagrant-active-directory/blob/master/scripts/importusers.ps1)
is the original source of truth — 300 realistic rows, plus one
hardcoded long-username edge case. The current AD assertions
(`a.legrand` → Amerigo Legrand, `m.mcnevin`, `x.guiu`, `a.blaskett`,
Andras-startswith filter, `longlong` sAMAccountName) all derive from
that file via the ps1's `uid = first[0].last` lowercased convention.

Goal: replace the homegrown data + provisioner with the **upstream
vagrant CSV used verbatim**, plus a small Python script per backend
that applies it. `docker compose up -d --wait` brings up two
backends populated identically from the same data — and the same
CSV stays usable against the original vagrant box manually.

## Scope

This refactor is the **docker-compose layer** only:

- Fixtures, compose file, provision scripts.
- Minimal PHP changes for credentials/domain naming so the existing
  tests can find the new servers.

Updating PHPUnit assertions to match the new data (in particular
`LDAPClientTest`, which today asserts against alice/bob/admins/devs/
ops — users and groups not present in the vagrant CSV) is a
**follow-up** and explicitly out of scope here.

## Source of truth

`_test/fixtures/users.csv` is byte-for-byte the upstream
`scripts/users.csv` — 300 rows, columns:

```
first,last,phone,mobile,group1,group2,group3,country,city,postal_code,company,street,title,department,homepage
```

The provision scripts derive everything else (matching
`importusers.ps1`):

- `uid` / sAMAccountName = `first[0].last` lowercased
  (e.g. `Amerigo Legrand` → `a.legrand`).
- UPN = `<uid>@example.com`.
- Email = `<uid>@example.com`.
- CN / `Name` = `"<first> <last>"`.
- Password = `Foo_b_ar123!` for every user.
- `PasswordNeverExpires = true` for every user (AD
  `userAccountControl = 66048`; OpenLDAP has no equivalent).
- Group memberships from `group1`/`group2`/`group3`; empty cells
  ignored.

One special user is added by the scripts (mirroring the ps1's
hardcoded "Very Long" / `longlong` block):

| Field            | Value                                    |
|---               |---                                       |
| sAMAccountName   | `longlong`                               |
| UPN              | `averylongusernamethatisverylong@example.com` |
| Name / CN        | `Very Long`                              |
| givenName        | `Very`                                   |
| sn               | `Long`                                   |
| mail             | `longlong@example.com`                   |

On OpenLDAP, the equivalent entry uses
`uid=averylongusernamethatisverylong` with the same name attributes
— OpenLDAP has no sAMAccountName/UPN concept.

`_test/fixtures/groups.csv` carries the four groups the ps1
hardcodes, with parent relationships in a `parent` column:

```csv
name,parent
alpha,
beta,
Gamma Nested,beta
omega nested,Gamma Nested
```

OpenLDAP ignores the `parent` column (posixGroup is flat); Samba
applies it via `samba-tool group addmembers`.

## Final layout

```
_test/
├── docker-compose.yml
└── fixtures/
    ├── groups.csv
    ├── users.csv                # upstream vagrant CSV, verbatim
    ├── openldap/
    │   ├── setup.sh             # bash: apt-get install ldap-utils, seed OUs
    │   └── provision.py         # python: read CSVs → ldapadd/ldapmodify
    └── samba/
        ├── setup.sh             # bash: wait, set pwd policy, drop in TLS
        └── provision.py         # python: read CSVs → samba-tool/ldbmodify
```

No Dockerfiles. Tools installed at startup (the OpenLDAP image
doesn't ship `ldap-utils`; `setup.sh` `apt-get install`s it,
gated on `command -v ldapadd` so restarts skip it). Both
provisioners are `.py` because the upstream CSV uses quoted
fields containing commas (e.g. `"Kemmer, Lesch and Leffler"`)
which bash `IFS=, read` can't parse — Python's `csv` module
reads it in two lines.

## Credentials and naming

| Setting                           | Value                                  |
|---                                |---                                     |
| Domain (both backends)            | `example.com`                          |
| Base DN (both backends)           | `dc=example,dc=com`                    |
| OpenLDAP admin DN                 | `cn=admin,dc=example,dc=com`           |
| AD admin                          | `Administrator`                        |
| Admin password (both)             | `Foo_b_ar123!`                         |
| Per-user password                 | `Foo_b_ar123!`                         |
| Email / UPN suffix                | `@example.com`                         |

DN strings are case-insensitive per RFC 4514, so a single
`dc=example,dc=com` works as the config value for both backends.
The DNs the servers *return* will be cased per backend (`DC=…`
from AD, `dc=…` from slapd), but config strings the tests pass
in don't need to differ.

## TLS

A one-shot `tls-init` service generates a single self-signed cert
covering `localhost` / `127.0.0.1` / `dc1.example.com` into a
named volume. Both backends read from the same volume.

The cert generation is **inline in compose** as a `command:`
string on the `tls-init` service — small enough that a sibling
`gen.sh` would just be noise. The inline `command:` runs:

```
apk add --no-cache openssl &&
[ -f /certs/cert.pem ] && exit 0 ||
openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
  -keyout /certs/key.pem -out /certs/cert.pem \
  -subj '/CN=localhost' \
  -addext 'subjectAltName=DNS:localhost,DNS:dc1.example.com,IP:127.0.0.1' &&
cp /certs/cert.pem /certs/ca.pem &&
chmod 644 /certs/*.pem
```

OpenLDAP and Samba both `depends_on: tls-init` with
`condition: service_completed_successfully` so the cert exists
before either starts.

- **OpenLDAP**: the `tls-certs` volume is mounted at
  `/container/service/slapd/assets/certs/`. osixia picks up the
  cert via `LDAP_TLS_CRT_FILENAME` / `LDAP_TLS_KEY_FILENAME` /
  `LDAP_TLS_CA_CRT_FILENAME` on first boot and serves both
  StartTLS (389) and LDAPS (636). Ports `1389:389` and
  `1636:636` exposed.
- **Samba**: the volume can't simply be mounted at
  `/var/lib/samba/private/tls/` because Samba's first-boot domain
  provisioning *generates and writes its own cert there*, which
  would either be blocked (read-only mount) or overwrite our cert
  (read-write). So the volume is mounted read-only at `/certs`,
  and `samba/setup.sh` (which runs **after** first-boot finishes)
  copies the three files into `/var/lib/samba/private/tls/` and
  `pkill -HUP samba` to reload. Ports `7389:389` and `7636:636`
  unchanged.

## Per-backend startup

### OpenLDAP

`setup.sh` (bash):
- `command -v ldapadd || apt-get update && apt-get install -y --no-install-recommends ldap-utils`
- create `ou=People,dc=example,dc=com` and `ou=Groups,…` via
  `ldapadd` (idempotent — probes existence first).

`provision.py` (python):
- `csv.DictReader` for `groups.csv` → `ldapadd` posixGroup entries.
- `csv.DictReader` for `users.csv` → for each row, derive
  `uid = first[0].last`, build LDIF with `inetOrgPerson` +
  `organizationalPerson` + `posixAccount` (+ `labeledURIObject` if
  homepage is set), hash password via `slappasswd -h '{SSHA}'`,
  pipe to `ldapadd`. Memberships via `ldapmodify` adding `memberUid`
  to the relevant `cn=<group>,ou=Groups,…`.
- Append the hardcoded long-name user as `uid=averylongusernamethatisverylong`.
- `touch /tmp/provisioned` at end. Idempotent: probes for
  `uid=a.legrand` and short-circuits if already present.

Attribute mapping (upstream column → LDAP attribute):

| CSV column     | OpenLDAP attribute | Samba (AD) attribute |
|---             |---                 |---                   |
| first          | givenName          | givenName            |
| last           | sn                 | sn                   |
| (derived)      | cn = "first last"  | cn / name = "first last" |
| (derived uid)  | uid                | sAMAccountName       |
| phone          | telephoneNumber    | telephoneNumber      |
| mobile         | mobile             | mobile               |
| country (2ltr) | c                  | c                    |
| city           | l                  | l                    |
| postal_code    | postalCode         | postalCode           |
| company        | o (organisation)   | company              |
| street         | street             | street               |
| title          | title              | title                |
| department     | departmentNumber   | department           |
| homepage       | labeledURI         | wWWHomePage          |

`title` carries the CSV's honorific value (Mr/Mrs/Dr/Ms/Rev) —
matches what `importusers.ps1` writes today, even though the
attribute is semantically the job title. Doing what AD does is
the point.

### Samba

`setup.sh` (bash):
- wait for `samba-tool user list` to succeed (first-boot domain
  provisioning takes 30–90s);
- `samba-tool domain passwordsettings set --max-pwd-age=42`
  (matches the Windows default that `ADClientTest::testMaxPasswordAge`
  asserts — explicit so it can't drift in newer samba releases);
- `cp /certs/{cert,key,ca}.pem /var/lib/samba/private/tls/`,
  `chmod 600 …/key.pem`, `pkill -HUP samba`.

`provision.py` (python):
- `csv.DictReader` for `groups.csv` → `samba-tool group add` for each
  row, then a second pass for `samba-tool group addmembers <parent> <name>`.
- `csv.DictReader` for `users.csv` → for each row, derive
  `uid = first[0].last`, run
  `samba-tool user create <uid> Foo_b_ar123! --given-name=… --surname=… --userprincipalname=<uid>@example.com --mail-address=<uid>@example.com --telephone-number=… --city=… --company=… --department=… --postal-code=… --street=…`
  (samba-tool exposes flags for most fields).
  For attributes samba-tool's CLI doesn't expose
  (`mobile`, `displayName`, `wWWHomePage`, `personalTitle`,
  `title` honorific, `userAccountControl=66048`), build an LDIF and
  pipe to `ldbmodify -H /var/lib/samba/private/sam.ldb`.
  Group memberships via `samba-tool group addmembers`.
- Append the hardcoded `longlong` / `Very Long` user via the same
  path with explicit `--userprincipalname=averylongusernamethatisverylong@example.com`.
- `touch /tmp/provisioned`. Idempotent: probes
  `samba-tool user show a.legrand`.

Default samba-tool behaviour without `--use-username-as-cn` sets
`CN = "<givenName> <surname>"`, matching what `New-ADUser -Name
"$first $last"` does in `importusers.ps1`. This is the Windows-AD
admin-tool convention; we follow it.

Samba auto-adds new users to `Domain Users` — no explicit
membership step. With ~300 users, `testGetDomainUsers` (>250)
satisfies itself.

## Compose file

```yaml
volumes:
  tls-certs:

services:
  tls-init:
    image: alpine:3.20
    volumes: ["tls-certs:/certs"]
    command: >
      sh -c "apk add --no-cache openssl >/dev/null &&
             [ -f /certs/cert.pem ] && exit 0 ||
             openssl req -x509 -newkey rsa:2048 -nodes -days 3650
               -keyout /certs/key.pem -out /certs/cert.pem
               -subj '/CN=localhost'
               -addext 'subjectAltName=DNS:localhost,DNS:dc1.example.com,IP:127.0.0.1' &&
             cp /certs/cert.pem /certs/ca.pem &&
             chmod 644 /certs/*.pem"

  openldap:
    image: osixia/openldap:1.5.0
    container_name: pureldap-openldap
    depends_on:
      tls-init: { condition: service_completed_successfully }
    environment:
      LDAP_ORGANISATION:        "Pureldap Test"
      LDAP_DOMAIN:              "example.com"
      LDAP_ADMIN_PASSWORD:      "Foo_b_ar123!"
      LDAP_TLS:                 "true"
      LDAP_TLS_CRT_FILENAME:    "cert.pem"
      LDAP_TLS_KEY_FILENAME:    "key.pem"
      LDAP_TLS_CA_CRT_FILENAME: "ca.pem"
      LDAP_TLS_VERIFY_CLIENT:   "never"
    ports: ["1389:389", "1636:636"]
    volumes:
      - ./fixtures:/fixtures:ro
      - tls-certs:/container/service/slapd/assets/certs
    post_start:
      - command: ["bash",    "/fixtures/openldap/setup.sh"]
      - command: ["python3", "/fixtures/openldap/provision.py"]
    healthcheck:
      test: ["CMD-SHELL", "test -e /tmp/provisioned"]
      interval: 5s
      retries: 60
      start_period: 30s

  samba:
    image: nowsci/samba-domain:latest
    container_name: pureldap-samba
    hostname: dc1
    domainname: example.com
    privileged: true
    depends_on:
      tls-init: { condition: service_completed_successfully }
    environment:
      DOMAIN:         "EXAMPLE.COM"
      DOMAINPASS:     "Foo_b_ar123!"
      DOMAIN_NETBIOS: "EXAMPLE"
      DOMAIN_EMAIL:   "admin@example.com"
      DNSFORWARDER:   "1.1.1.1"
      HOSTIP:         "127.0.0.1"
      INSECURELDAP:   "true"
    ports: ["7389:389", "7636:636"]
    volumes:
      - ./fixtures:/fixtures:ro
      - tls-certs:/certs:ro
    post_start:
      - command: ["bash",    "/fixtures/samba/setup.sh"]
      - command: ["python3", "/fixtures/samba/provision.py"]
    healthcheck:
      test: ["CMD-SHELL", "test -e /tmp/provisioned"]
      interval: 5s
      retries: 120
      start_period: 60s
```

`post_start` commands run sequentially: setup completes before
provision touches the sentinel.

## PHP-side updates (minimum required by this refactor)

Just credential/domain rewires so the existing PHP tests can still
reach the new servers. Updating any test that asserts against
alice/bob/admins/devs/ops is deferred.

- `_test/AuthTest.php`: `admin_username=Administrator`,
  `admin_password=Foo_b_ar123!`, `base_dn=dc=example,dc=com`,
  `suffix=example.com`.
- `_test/ADClientTest.php`: same admin/base_dn/suffix; in
  `testGetUser` change the DN expectation to
  `CN=Amerigo Legrand,CN=Users,DC=example,DC=com` and the
  `getUser(...)` argument to `a.legrand@example.com`; same for the
  `m.albro@example.local` lookup in `testGetUserRecursiveGroups`.
- `_test/GroupHierarchyCacheTest.php`: same admin/base_dn/suffix;
  DN expectations updated to `…,DC=example,DC=com`.
- `_test/integration/LDAPClientTest.php`: `base_dn`, `usertree`,
  `grouptree`, admin DN all switch to `dc=example,dc=com`. The
  alice-based test bodies are flagged as TODO (deferred — they
  reference data that no longer exists; rewriting them to use
  vagrant-CSV users is follow-up work).
- `_test/RequiresAD.php`: drop the `vagrant-active-directory`
  reference in the docblock and point at this compose file.
- `PLAN.md`: strip remaining "vagrant" mentions (lines 371, 493).

## Files

Created:
- `_test/fixtures/groups.csv`
- `_test/fixtures/users.csv` (copy of upstream verbatim)
- `_test/fixtures/openldap/setup.sh`
- `_test/fixtures/openldap/provision.py`
- `_test/fixtures/samba/setup.sh`
- `_test/fixtures/samba/provision.py`

Edited:
- `_test/docker-compose.yml` — full rewrite per the block above.
- `.github/workflows/phpTestIntegration.yml` — drop the
  `/tmp/provision.log` cat lines; both scripts print straight to
  stdout (captured by `docker compose logs`).
- The PHP test files listed under "PHP-side updates".

Deleted:
- `_test/fixtures/provision.py`
- `_test/fixtures/users.json`

## Verification

Docker-compose layer is the primary deliverable:

```bash
cd _test

# 1. Bring it up clean from scratch
docker compose down -v
docker compose up -d --wait
docker compose ps   # all services Healthy

# 2. Cert is the same on both backends, covers localhost
for p in 1636 7636; do
  openssl s_client -connect localhost:$p -showcerts </dev/null 2>/dev/null \
    | openssl x509 -noout -text \
    | grep -E 'Subject:|DNS:|IP'
done
# Both should print Subject CN=localhost and SAN: DNS:localhost,
# DNS:dc1.example.com, IP Address:127.0.0.1

# 3. OpenLDAP data sanity — StartTLS + LDAPS
ldapsearch -x -H ldap://localhost:1389 -ZZ \
  -D "cn=admin,dc=example,dc=com" -w "Foo_b_ar123!" \
  -b "dc=example,dc=com" "(uid=a.legrand)" dn givenName sn mail
ldapsearch -x -H ldaps://localhost:1636 \
  -D "cn=admin,dc=example,dc=com" -w "Foo_b_ar123!" \
  -b "dc=example,dc=com" "(uid=a.legrand)" dn
# → Amerigo Legrand, mail a.legrand@example.com

# 4. Samba data sanity
docker exec pureldap-samba samba-tool user show a.legrand
docker exec pureldap-samba samba-tool user show longlong
docker exec pureldap-samba samba-tool group listmembers alpha | wc -l
# alpha ≈ 92

# 5. Idempotency: re-running provision must be a no-op
docker exec pureldap-openldap python3 /fixtures/openldap/provision.py
docker exec pureldap-samba    python3 /fixtures/samba/provision.py
# both print "already provisioned" and exit 0

# 6. Clean teardown
docker compose down -v
```

When all six pass the docker-compose deliverable is done. PHPUnit
updates against the same fixtures are the next, separate step.

## Known carry-overs

- OpenLDAP `posixGroup` is flat — the `parent` column in
  `groups.csv` is parsed but unused on the OpenLDAP side. AD-side
  recursive-group tests still cover the nesting code path.
- TLS-cert install and AD password-policy live in `samba/setup.sh`
  (not a custom image) because Samba's first-boot provisioning
  generates its own cert and would overwrite anything baked in.
  The compose lifecycle hook is the right seam.
- `ldap-utils` install in `openldap/setup.sh` is at startup, per
  the no-Dockerfile direction; the install is gated on
  `command -v ldapadd` so restarts skip the apt step.
- `LDAPClientTest` currently asserts against `alice` / `bob` /
  `admins` / `devs` / `ops` — none of those exist in the
  upstream vagrant CSV. Rewriting those assertions to use
  vagrant-CSV users and groups (`a.legrand`, `alpha`/`beta`/…) is
  follow-up work, not part of this refactor.
