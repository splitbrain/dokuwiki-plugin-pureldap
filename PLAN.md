# Make pureldap a universal LDAP auth plugin

## Context

The pureldap plugin (`/home/user/dokuwiki-plugin-pureldap`) was created to
replace DokuWiki's two bundled LDAP auth plugins — `authad` (raw `ldap_*` +
adLDAP wrapper, AD-only) and `authldap` (raw `ldap_*`, generic RFC 2307) —
with a single modern plugin built on the FreeDSx pure-PHP LDAP library. The
abstraction is half-done: `classes/Client.php` is an abstract base with
shared infrastructure (FreeDSx connection, TLS, caching, SSO via
`REMOTE_USER`, paged search, logging) and a few abstract methods. Only one
concrete subclass exists — `ADClient` — and `auth.php:31` and `auth.php:62`
hardcode `new ADClient($this->conf); // FIXME decide class on config`.

### Rethink: AD is LDAP-plus-defaults, not a peer

Most of what's in `ADClient` today is not AD-specific protocol behaviour;
it's *generic LDAP with AD's well-known schema conventions hardcoded*. Once
you strip those defaults out into config, only a small core of true AD
protocol remains:

| Truly AD-specific (cannot be reduced to config) | Just "AD's default schema" (configurable) |
|---|---|
| `unicodePwd` attribute + UTF-16LE-quoted password encoding | `objectClass=user` / `objectClass=group` filters |
| `maxPwdAge` global password policy at base DN | `sAMAccountName` / `displayName` / `cn` / `mail` attribute names |
| `pwdlastset` Windows FILETIME parsing | `memberOf` attribute walk + DN→CN extraction |
| `userAccountControl` bitmask (`ADS_UF_DONT_EXPIRE_PASSWD`) | Recursive group traversal via `memberOf` chains |
| `primaryGroupID=513` → "Domain Users" RID trick | `objectCategory=group` in hierarchy cache (`objectClass=group` also works in AD) |
| AD bind sub-codes (52f/530/.../773 in "data XXX" string) | UPN suffix on the user (it's just `userPrincipalName`) |
| `userPrincipalName` semantics during *bind* (UPN qualification) | The user-search filter `(|(sAMAccountName=X)(userPrincipalName=X))` |

So the correct hierarchy is **`ADClient extends LDAPClient extends Client`**.
`LDAPClient` becomes the real universal implementation, and `ADClient` is a
thin specialisation that pre-seeds AD schema defaults plus overrides the
handful of methods that touch real AD protocol.

Outcome: pureldap becomes the single, modern auth plugin for any LDAP-style
backend; AD support is achieved by inheriting from `LDAPClient` and
specialising the AD-protocol bits; `authad` and `authldap` can be
deprecated upstream.

## Design overview

### Class hierarchy

```
Client (abstract)            — connection, bind, cache, SSO, attr2str,
                                logging; concrete setPassword() template;
                                abstract: getUserEntry, passwordAttribute,
                                encodePassword, getUser, getGroups,
                                getFilteredUsers, cleanUser, cleanGroup
 └── LDAPClient (concrete)   — universal LDAP impl: configurable filter
                                templates (FilterTemplate), bind modes,
                                memberOf or grouptree group resolution,
                                userPassword/SSHA password change.
                                Full bodies of entry2User, getUserGroups,
                                getFilteredUsers live here and call small
                                hooks for the few AD-protocol differences:
                                  - extractLastpwd(Entry): int = 0
                                  - extractExpires(Entry): bool = false
                                  - additionalGroups(Entry): array = []
                                  - groupMembershipFilter(string $dn)
                                       = Filters::equal('memberOf', $dn)
      └── ADClient (concrete) — AD specialisation, all small overrides:
                                  - prepareConfig() seeds AD defaults
                                  - passwordAttribute() → unicodePwd
                                  - encodePassword() → UTF-16LE quoted
                                  - extractLastpwd() — pwdlastset FILETIME
                                  - extractExpires() — UAC bitmask test
                                  - additionalGroups() — primary group when
                                    primaryGroupID==513
                                  - groupMembershipFilter() — substitute
                                    primaryGroupID=513 for primary group dn
                                  - cleanUser() strips UPN/DOMAIN\ qualifiers
                                  - prepareBindUser() applies UPN suffix
                                  - getMaxPasswordAge() queries maxPwdAge
                                  - translateBindException() AD bind codes
                                  - canModPass() encryption-gated
                                  - supportsPasswordExpiry() = true
                                  - helpers qualifiedUser, simpleUser
```

Net effect: `ADClient` shrinks dramatically. Today it owns roughly 450
lines; after this refactor it's ~12 small methods (most one-liners or
short bodies) plus two AD-only helpers. The full bodies of `entry2User`,
`getUserGroups`, and `getFilteredUsers` move into `LDAPClient` and serve
both subclasses via the hook points above. The shape of `ADClient`
becomes essentially "a config object plus seven tiny override hooks" —
it tells you precisely what AD does differently from generic LDAP at the
protocol level, no more, no less.

Side benefit of the hook pattern: future subclasses (e.g. `FreeIPAClient`
for Kerberos-aware password expiry via `krbPasswordExpiration`) become
trivial — implement the relevant hooks, inherit everything else.

### Driver selection — dedicated factory class

- New config `directory_type` with values `ad` (default) and `ldap`.
- New `classes/ClientFactory.php`:
  `public static function create(array $conf): Client`. Returns `ADClient`
  for `ad`, `LDAPClient` for `ldap`. Unknown values fall back to `ad` with
  `Logger::error()`.
- `auth.php` calls `ClientFactory::create($this->conf)` in both places
  that today say `new ADClient(...)`.

A separate factory class keeps `Client` free of knowledge about its
subclasses and gives tests a single mock seam.

### What moves up from ADClient into LDAPClient

These methods currently live in `ADClient` but the behaviour they encode
is generic LDAP, just with AD's conventional attribute/filter values
hardcoded. They move up into `LDAPClient`, parameterised by config:

- **`getUserEntry($username)`** — search `usertree` with `userfilter`
  (template-substituted). AD's two-attribute search (`sAMAccountName` OR
  `userPrincipalName`) becomes the AD-seeded default value of `userfilter`.
- **`getUser($username, $fetchgroups)`** — calls `getUserEntry()` →
  `entry2User()`. Already generic; no change needed beyond moving the file.
- **`getGroups($match, $filtermethod)`** — paged search using `grouptree` +
  `groupfilter`, returning the attribute named by `groupkey`. AD's
  `objectClass=group` / `cn` become AD-seeded defaults.
- **`entry2User(Entry $entry)`** — full body lives here: read `userkey` for
  canonical user, `mapping_name` (default `displayName` / fall back to
  `cn`) for name, `mapping_mail` for mail, `dn`, plus configured extra
  `attributes` and `mapping_*` regex extraction. Calls two hooks for
  optional password-lifecycle data:
  - `extractLastpwd(Entry): int` — base returns `0`; `ADClient` decodes
    the `pwdlastset` Windows FILETIME.
  - `extractExpires(Entry): bool` — base returns `false`; `ADClient`
    tests `userAccountControl & ADS_UF_DONT_EXPIRE_PASSWD`.
  When non-zero/true, the result is set on the user info array as
  `lastpwd` / `expires`. This hook design also lets future subclasses
  (FreeIPA's `krbPasswordExpiration`, etc.) wire their own decoders
  without touching the generic body.
- **`getUserGroups(Entry $userentry)`** — memberOf walk + DN→CN extraction,
  optional recursion via `GroupHierarchyCache`. Calls
  `$this->additionalGroups($userentry)` (returns `[]` in `LDAPClient`,
  overridden in `ADClient` to append the primary group when
  `primaryGroupID==513`).
- **`getFilteredUsers($match, $filtermethod)`** — generic body: build the
  user filter from `match['user']` (→ `userkey`), `match['name']`
  (→ configured name attr), `match['mail']`, and `match['grps']` →
  resolve to a set of group DNs and OR-in `$this->groupMembershipFilter($dn)`
  clauses. `LDAPClient::groupMembershipFilter()` returns
  `Filters::equal('memberOf', $dn)`. `ADClient` overrides to substitute
  `Filters::equal('primaryGroupID', 513)` when `dn2group($dn)` is the
  configured primary group.
- **`cleanGroup()`** — lowercases (already generic; today it lives in
  ADClient).
- **`dn2group($dn)`** — extract CN from DN. Generic.
- **`GroupHierarchyCache`** — see below.

`LDAPClient::userAttributes()` returns `dn`, `userkey`, `mapping_name`'s
attribute, `mapping_mail`'s attribute, plus configured `attributes` and
(when `group_strategy=memberof`) `memberOf`. `ADClient::userAttributes()`
calls parent and appends `pwdlastset`, `useraccountcontrol`,
`primaryGroupID`.

### What stays in (or moves to) ADClient

True AD protocol, no config can fix it:

- **`prepareConfig()`** — seeds AD-aware defaults for the universal knobs
  before merging user-supplied config:
  ```
  userfilter   = '(&(objectClass=user)(|(sAMAccountName=%{user})(userPrincipalName=%{user})))'
  groupfilter  = '(objectClass=group)'
  userkey      = 'sAMAccountName'
  groupkey     = 'cn'
  mapping_name = 'displayName'  (fall back to 'name' via regex form)
  usertree     = $config['base_dn']
  grouptree    = $config['base_dn']
  group_strategy = 'memberof'
  ```
  Then `parent::prepareConfig()` merges in `conf/default.php` (which only
  fills genuinely empty keys) and user config. AD admins can still
  override any of these in `local.protected.php` if their forest is
  unusual.
- **`passwordAttribute(): string`** → `'unicodePwd'`.
- **`encodePassword(string)`** → UTF-16LE quoted (current implementation
  unchanged).
- **`extractLastpwd(Entry): int`** — decode `pwdlastset` (Windows FILETIME
  in 100-ns intervals from 1601 → Unix epoch).
- **`extractExpires(Entry): bool`** — test
  `userAccountControl & ADS_UF_DONT_EXPIRE_PASSWD`.
- **`additionalGroups(Entry $userentry): array`** — return
  `[$this->cleanGroup($this->config['primarygroup'])]` when
  `primaryGroupID==513`, else `[]`.
- **`groupMembershipFilter(string $groupDn): FilterInterface`** — return
  `Filters::equal('primaryGroupID', 513)` when `dn2group($groupDn)` is
  the configured primary group; else delegate to
  `parent::groupMembershipFilter($groupDn)`.
- **`cleanUser($user)`** — strip UPN suffix and `DOMAIN\` prefix, then
  lowercase (`simpleUser()` today). LDAPClient's `cleanUser()` only
  lowercases.
- **`prepareBindUser($user)`** — apply UPN suffix via `qualifiedUser()`.
- **`getMaxPasswordAge()`** — query `maxPwdAge` at base DN (unchanged).
- **`translateBindException(\Exception): ?array`** — the AD bind code
  table moved from `auth.php::parseErrorCodesToMessages()`. Returns
  `null` or `['key' => 'ERROR_PASSWORD_EXPIRED', 'allowReset' => bool]`.
- **`supportsPasswordExpiry(): bool`** → `true`.
- **Helpers**: `qualifiedUser()`, `simpleUser()`, `dn2group()` if not
  promoted.

### Base `Client` additions (apply to all subclasses)

- Promote `getUserEntry($username): ?Entry` to abstract.
- Concrete `setPassword($user, $newpass, $oldpass = null)` as a template
  method: `autoAuth`, look up via `getUserEntry()`, optional rebind for
  self-service, build modifications using `passwordAttribute()` and
  `encodePassword()`, call `$this->ldap->update($entry)`. Removes the
  near-duplicate `setPassword()` from `ADClient` and avoids re-writing it
  in `LDAPClient`.
- Concrete `translateBindException(\Exception $e): ?array` returning
  `null`.
- Concrete `canModPass(): bool` returning a sane default (false). AD
  overrides to encryption-gated. LDAP overrides to the `modPass` config.
- Concrete `supportsPasswordExpiry(): bool` returning `false`.
- Remove the AD-specific lines from `Client::prepareConfig()` (`suffix`
  lowercase + `@` strip; `primarygroup` lowercase). These move into
  `ADClient::prepareConfig()`.

### LDAPClient specifics

User search:
- `usertree` + `userfilter` with placeholder substitution: `%{user}`,
  `%{server}`, `%{dn}`, `%{gid}`. Run through `FilterTemplate::substitute()`,
  hand the resulting RFC 4515 string to FreeDSx's filter parser.
- `userscope`: `sub`|`one`|`base`, mapped to FreeDSx scope.
- `userkey` (default `uid`) is the canonical username.
- `mapping_name`, `mapping_mail`, `mapping_grps` accept either an attribute
  name or an `attr/regex/` shorthand for regex extraction (matches
  authldap's `[key => regexp]` mapping form, flattened for the config
  manager).

Bind modes (three, mirroring authldap):
1. `binddn` template containing `%{user}` → direct user bind.
2. `admin_username` + `admin_password` set → service-account bind, search,
   rebind as user.
3. Otherwise anonymous bind, search, rebind.

Group resolution — explicit `group_strategy` config (`auto` | `grouptree`
| `memberof` | `none`, default `auto`):
- `auto` resolves at runtime to `grouptree` if `groupfilter` is set, else
  `memberof` if user entry carries `memberOf`, else `none`.
- `grouptree`: search `grouptree` with `groupfilter` template (RFC 2307 /
  posixGroup); read `groupkey` (default `cn`).
- `memberof`: DN→CN extraction from the user's `memberOf` attribute.
  `recursivegroups=1` plus this strategy triggers `GroupHierarchyCache`.
- `none`: only `defaultgroup`.

Password change:
- `passwordAttribute()` → `'userPassword'`.
- `encodePassword()` → SSHA via `dokuwiki\PassHash::hash_ssha()`, or
  plaintext when `modPassPlain` is on (mirrors authldap).

`cleanUser` / `cleanGroup`:
- `LDAPClient::cleanUser()` — lowercase via `PhpString::strtolower()`.
- `LDAPClient::cleanGroup()` — lowercase (matches ADClient and today's
  ADClient behaviour).

### `FilterTemplate` helper

New `classes/FilterTemplate.php` with two static methods ported verbatim
from `authldap.php:462-535`:
- `substitute(string $template, array $placeholders): string`
- `filterEscape(string $value): string`

Centralised so it's unit-testable without LDAP and shareable between any
subclass that wants templated filters.

### `GroupHierarchyCache` generalisation

Traversal is already generic. Only the population query is bespoke
(`classes/GroupHierarchyCache.php:71-99`). Refactor the constructor:

```
__construct(
    LdapClient $ldap,
    bool $usefs,
    FilterInterface $filter,
    string $parentAttr = 'memberOf',
    string $nameAttr   = 'cn',
    string $cacheKey   = 'grouphierarchy'
)
```

The fscache filename must include a hash of `$filter` + `$parentAttr` so
AD and LDAP installs (or installs that change `group_strategy`) don't
share cache files. `LDAPClient` constructs the cache with a filter
derived from its `groupfilter` config or a sensible default. `ADClient`
inherits the same construction path — its AD-seeded `groupfilter`
(`(objectClass=group)`) works fine for the cache; `objectCategory=group`
is not needed (the previous hardcode was a minor inefficiency rather
than a requirement).

### Auth plugin (`auth.php`)

- Replace both `new ADClient(...)` calls with
  `ClientFactory::create($this->conf)`.
- `$this->cando['modPass'] = $this->client->canModPass()` instead of the
  encryption-vs-none branch.
- `cleanGroup($group)` delegates to `$this->client->cleanGroup($group)`.
  ⚠ BC: today `auth.php::cleanGroup` returns `$group` unchanged while
  ADClient's `cleanGroup` lowercases — fixing the delegation will start
  lowercasing on the way out for existing AD users. Call this out in the
  migration notes; do not silently break BC.
- `parseErrorCodesToMessages()` shrinks to a caller of
  `$this->client->translateBindException($e)` that handles localisation
  and (for `allowReset` results) renders the `wl()`-based reset link.
  Link rendering stays in `auth.php` because it needs `wl()` + `canDo()`.

### `action/expiry.php`

- Gate hook registration on `$auth->client->supportsPasswordExpiry()`
  rather than always registering and letting `getMaxPasswordAge()` return
  0. Avoids unnecessary global-policy lookups for LDAPClient installs.

### Config layout

Add to `conf/default.php` / `conf/metadata.php` / `lang/en/settings.php`:

| Key | Type | Notes |
|---|---|---|
| `directory_type` | multichoice `ad`\|`ldap` | default `ad` |
| `usertree` | string | AD: defaults to `base_dn` via `ADClient::prepareConfig()` |
| `grouptree` | string | AD: defaults to `base_dn` |
| `userfilter` | string | AD default seeded by ADClient |
| `groupfilter` | string | AD default `(objectClass=group)` |
| `userscope` | multichoice `sub`\|`one`\|`base` | default `sub` |
| `groupscope` | multichoice `sub`\|`one`\|`base` | default `sub` |
| `userkey` | string | AD default `sAMAccountName`, generic default `uid` |
| `groupkey` | string | default `cn` |
| `binddn` | string | optional user-bind DN template |
| `mapping_name` | string | attribute or `attr/regex/` form |
| `mapping_mail` | string | same |
| `mapping_grps` | string | same |
| `group_strategy` | multichoice `auto`\|`grouptree`\|`memberof`\|`none` | default `auto` (AD `prepareConfig` forces `memberof`) |
| `modPass` | onoff | default 1; drives `LDAPClient::canModPass()` |
| `modPassPlain` | onoff | default 0 |

Reuse existing keys for both modes: `servers`, `port`, `encryption`,
`validate`, `admin_username`, `admin_password`, `attributes`,
`recursivegroups`, `usefscache`, `page_size`, `sso`, `sso_charset`,
`expirywarn`.

AD-only existing keys: `suffix`, `primarygroup`.

Mode-applicable options labelled in `lang/en/settings.php` with
`[AD only]` / `[LDAP only]` / `[both]` prefixes since the config manager
can't conditionally hide fields.

### Multi-domain

Deferred to a follow-up. `authad`'s multi-domain dispatch
(`[domain]` sub-arrays + a UI selector in `authad/action.php`) is broad
enough that folding it in here doubles scope. Document as a known
regression for multi-domain authad users; add a tracking issue.

### Tests

Three tiers:
1. **Pure unit (no server)**: `FilterTemplateTest`, `ClientFactoryTest`,
   `ADClient::translateBindException` table coverage; a refactored
   `GroupHierarchyCacheTest` injecting a fake `LdapClient` to exercise the
   parameterised constructor.
2. **AD integration (existing)**: keep `_test/ADClientTest.php`,
   `_test/AuthTest.php`, `_test/GeneralTest.php`,
   `_test/GroupHierarchyCacheTest.php` running against the Samba AD-DC
   fixture on `localhost:7389`; skip cleanly when unreachable. With AD
   now inheriting from `LDAPClient`, these tests also exercise the
   universal code path — strong regression coverage.
3. **LDAP integration (new)**: `_test/integration/LDAPClientTest.php`
   gated on `LDAP_TEST_HOST`; ship a `_test/docker-compose.openldap.yml`
   using `osixia/openldap` with sample posix users/groups and the
   memberOf overlay enabled.

## Files to change

- `auth.php` — factory call; `cando['modPass']` via `canModPass()`;
  delegate `cleanGroup` to client; thin error-code handling via
  `translateBindException()`.
- `classes/Client.php` — slim `prepareConfig()`; promote `getUserEntry()`
  to abstract; add concrete `setPassword()` template plus abstract
  `passwordAttribute()` / `encodePassword()`; add concrete
  `translateBindException()`, `canModPass()`,
  `supportsPasswordExpiry()` defaults.
- `classes/LDAPClient.php` (new) — receives most of today's `ADClient`
  body, parameterised by config: `getUserEntry`, `getUser`, `getGroups`,
  full bodies of `entry2User`, `getUserGroups` (memberof + recursion),
  `getFilteredUsers`; hook defaults (`extractLastpwd`, `extractExpires`,
  `additionalGroups`, `groupMembershipFilter`); `cleanUser` (lowercase
  only), `cleanGroup`, `dn2group`, `prepareBindUser` (no-op or `binddn`
  template), `userAttributes` (generic set), `canModPass`
  (config-driven), `passwordAttribute` (`userPassword`), `encodePassword`
  (SSHA/plain).
- `classes/ADClient.php` — shrinks to twelve small methods plus two
  helpers: `prepareConfig` (seeds AD defaults); protocol overrides
  `passwordAttribute`, `encodePassword`, `prepareBindUser`,
  `getMaxPasswordAge`, `translateBindException`, `canModPass`,
  `supportsPasswordExpiry`, `cleanUser`; hook overrides
  `extractLastpwd`, `extractExpires`, `additionalGroups`,
  `groupMembershipFilter`; helpers `qualifiedUser`, `simpleUser`.
- `classes/ClientFactory.php` (new) — one `create()` method.
- `classes/FilterTemplate.php` (new) — `substitute`, `filterEscape`.
- `classes/GroupHierarchyCache.php` — parameterised constructor; hash
  filter into fscache filename. Existing AD callsite passes today's
  effective filter (the AD-seeded `groupfilter`).
- `conf/default.php` and `conf/metadata.php` — new keys per the table
  above; default `directory_type=ad` for BC.
- `lang/en/settings.php` and `lang/en/lang.php` — labels for new keys;
  applicability prefixes; generic LDAP bind-failure string.
- `action/expiry.php` — gate registration on
  `$auth->client->supportsPasswordExpiry()`.
- `README` — migration table mapping `authad` and `authldap` keys to
  pureldap equivalents; flag known regressions (multi-domain,
  `version`/`referrals`/`deref` if FreeDSx doesn't expose them,
  `cleanGroup` lowercasing).
- `plugin.info.txt` — bump date; description → "Universal LDAP auth
  plugin (AD and generic)".
- `_test/FilterTemplateTest.php`, `_test/ClientFactoryTest.php`,
  `_test/integration/LDAPClientTest.php`,
  `_test/docker-compose.openldap.yml` (new).

## Reused existing utilities

- FreeDSx (already a dep): `LdapClient::bind`, `search`, `update`,
  `paging`, `startTls`; `Operations::search()`, `Operations::modify()`;
  `Search\Filters::*` and the FreeDSx filter parser for raw filter
  strings.
- `dokuwiki\PassHash::hash_ssha()` from DokuWiki core for SSHA hashing in
  `LDAPClient::encodePassword()`.
- `Client::getCachedUser()`, `getCachedGroups()`, `authenticate()`,
  `prepareSSO()`, `attr2str()`, `autoAuth()` — unchanged.
- `auth_getCookie()` / `auth_decrypt()` / `auth_cookiesalt()` from
  DokuWiki core — `LDAPClient` can replicate authldap's rebind-during-
  getUserData flow (`authldap.php:181-185`) so subscription emails work
  outside the login path.
- Port `makeFilter()` (`authldap.php:462-477`) and `filterEscape()`
  (`authldap.php:527-535`) into `FilterTemplate`.

## Implementation order (each step keeps the plugin green)

1. **Pure refactor of `Client`, no behaviour change.** Lift AD-specific
   bits out of `Client::prepareConfig()`. Promote `getUserEntry()` to
   abstract. Add `setPassword()` template + `passwordAttribute()` /
   `encodePassword()` abstract hooks (ADClient implements). Add
   `translateBindException()`, `canModPass()`, `supportsPasswordExpiry()`
   concrete defaults. Move `parseErrorCodesToMessages` into
   `ADClient::translateBindException()` returning a struct; adapt
   `auth.php`. Add `ClientFactory` returning `ADClient` only. Existing AD
   tests must still pass.
2. **Generalise `GroupHierarchyCache`** — parameterise constructor + hash
   filter into cache filename. Existing ADClient passes today's filter.
   Tests must still pass.
3. **Introduce `LDAPClient` by extracting from `ADClient`.** Move the
   generic bodies (`getUserEntry`, `getUser`, `getGroups`, *full*
   `entry2User`, *full* `getUserGroups` memberof+recursion, *full*
   `getFilteredUsers`, `cleanGroup`, `dn2group`, `userAttributes`
   generic set) into a new `LDAPClient` class. Define the four hook
   methods (`extractLastpwd`, `extractExpires`, `additionalGroups`,
   `groupMembershipFilter`) with neutral defaults on `LDAPClient`.
   `ADClient extends LDAPClient` and overrides only the hooks plus the
   small AD-protocol methods. The AD-seeded defaults move into
   `ADClient::prepareConfig()`. After this step, with
   `directory_type=ad`, behaviour is identical to today — verified by AD
   integration tests, which simultaneously exercise the new universal
   code path.
4. **Add `FilterTemplate`** + unit tests. Wire `LDAPClient` to use it.
   `ADClient::prepareConfig()` keeps seeding the AD-format filter
   strings; `LDAPClient` templates work for both subclasses.
5. **Add `directory_type` config**. `ClientFactory` honours it.
6. **Add LDAP-only config keys** (`usertree`, `grouptree`, `userfilter`,
   `groupfilter`, `userscope`, `groupscope`, `userkey`, `groupkey`,
   `binddn`, `mapping_*`, `group_strategy`, `modPass`, `modPassPlain`)
   to `conf/default.php` + `conf/metadata.php` + lang.
7. **Round out `LDAPClient` bind modes** (anonymous + service account +
   user-bind template) and `group_strategy` `auto` resolution.
8. **Gate `action/expiry.php`** on `supportsPasswordExpiry()`.
9. **Integration tests**: `_test/integration/LDAPClientTest.php` +
   `docker-compose.openldap.yml`.
10. **Docs**: README migration table; flag `cleanGroup` BC; bump
    `plugin.info.txt`.

## Verification

End-to-end smoke tests, run in order:

1. **AD regression** — with `directory_type=ad` (default), run all of
   `_test/ADClientTest.php`, `_test/AuthTest.php`,
   `_test/GroupHierarchyCacheTest.php`, `_test/GeneralTest.php` against
   the Samba AD-DC fixture. All must pass. (After step 3, these
   simultaneously exercise the new `LDAPClient` base path.)
2. **AD live login** — bring up a DokuWiki against an AD with the
   existing pureldap config; verify login, group listing, user listing,
   password change, expiry warning, reset-link rendering on
   `ERROR_PASSWORD_EXPIRED` / `ERROR_PASSWORD_MUST_CHANGE`.
3. **LDAP unit** — run `_test/FilterTemplateTest.php` and
   `_test/ClientFactoryTest.php` (no server).
4. **LDAP integration (grouptree)** —
   `docker compose -f _test/docker-compose.openldap.yml up`,
   set `LDAP_TEST_HOST`. Configure: `directory_type=ldap`,
   `usertree=ou=users,dc=example,dc=org`,
   `userfilter=(&(uid=%{user})(objectClass=posixAccount))`,
   `grouptree=ou=groups,dc=example,dc=org`,
   `groupfilter=(&(objectClass=posixGroup)(memberUid=%{user}))`,
   `group_strategy=grouptree`. Verify: bind in all three modes,
   getUserData returns `name`/`mail`/`grps`, retrieveUsers paginates,
   retrieveGroups, password change writes SSHA to `userPassword`.
5. **LDAP memberof + recursive** — same fixture with memberOf overlay,
   `group_strategy=memberof`, `recursivegroups=1`; verify group
   resolution and nested groups via `GroupHierarchyCache`.
6. **Migration smoke** — take a working `authldap` config and translate
   it to pureldap using the README table; confirm parity for one real
   directory.

## Open items / risks to flag during implementation

- **`cleanGroup` BC.** Delegating to the client changes observable
  output for AD users (groups lowercased). Document in migration notes;
  consider keeping the no-op for one release if BC is sacred.
- **FreeDSx `referrals` / `deref`.** Confirm what FreeDSx exposes
  before promising parity with authldap. If unsupported, drop those
  keys rather than silently ignoring.
- **FreeDSx multi-server failover.** authldap loops `servers` in
  `openLDAP()` taking the first reachable. pureldap passes the array
  straight to FreeDSx — verify the failover semantics match; if not,
  add an explicit loop in `Client::__construct()` or document the
  difference.
- **`isCaseSensitive()`** hardcoded `false` today. Reconsider per-client
  override if a generic LDAP user reports false matches (RFC 2307 `uid`
  can be case-sensitive on some schemas).
- **AD-seeded default override semantics.** `ADClient::prepareConfig()`
  must seed defaults *before* parent merges in `conf/default.php`,
  otherwise user-provided values can't override. Verify the merge order
  in tests.
- **Multi-domain.** Deferred; tracked as a follow-up.
