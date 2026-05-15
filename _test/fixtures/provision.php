#!/usr/bin/env php
<?php

/**
 * Apply users.json to both LDAP backends.
 *
 * Three classes:
 *   Provisioner          — abstract base. Driver loop and shared helpers.
 *   OpenLDAPProvisioner  — implements the per-entity methods via ldapadd /
 *                          ldapmodify against the openldap service.
 *   SambaProvisioner     — implements them via docker-exec → samba-tool /
 *                          ldbmodify against the samba container.
 *
 * The spec is plain data — no backend tags, no connection info, no
 * per-backend conditions. Each subclass reads its own connection
 * settings from environment variables (set on the provisioner service
 * in docker-compose.yml) and decides how to express the spec's fields
 * against its backend (e.g. posixAccount uidNumber is auto-assigned;
 * passwordNeverExpires becomes a userAccountControl override on AD
 * and a no-op on slapd).
 *
 * Both run() invocations are idempotent: each backend probes for the
 * canonical 'alice' entry and short-circuits if she's already there,
 * so re-running this script against a populated fixture is a no-op.
 */

const SPEC_PATH = __DIR__ . '/users.json';

abstract class Provisioner
{
    protected array $spec;

    public function __construct(array $spec)
    {
        $this->spec = $spec;
    }

    public function run(): void
    {
        $name = (new ReflectionClass($this))->getShortName();
        $this->waitUntilReady();
        if ($this->isAlreadyProvisioned()) {
            echo "[{$name}] already provisioned, skipping\n";
            return;
        }
        echo "[{$name}] provisioning...\n";

        $this->ensureRoot();
        $this->applyPasswordPolicy();

        foreach ($this->spec['groups'] as $g) {
            $this->addGroup($g);
        }
        foreach ($this->spec['groups'] as $g) {
            foreach ($g['contains'] ?? [] as $inner) {
                $this->addGroupToGroup($g['name'], $inner);
            }
        }
        foreach ($this->spec['users'] as $u) {
            $this->addUser($u);
        }
        foreach ($this->spec['users'] as $u) {
            foreach ($u['memberOf'] ?? [] as $group) {
                $this->addUserToGroup($u['uid'], $group);
            }
        }
        if (isset($this->spec['padding'])) {
            $this->addPaddingUsers($this->spec['padding']);
        }
        $this->finalize();
        echo "[{$name}] done\n";
    }

    abstract protected function waitUntilReady(): void;
    abstract protected function isAlreadyProvisioned(): bool;
    abstract protected function ensureRoot(): void;
    abstract protected function applyPasswordPolicy(): void;
    abstract protected function addGroup(array $g): void;
    abstract protected function addUser(array $u): void;
    abstract protected function addUserToGroup(string $uid, string $group): void;
    abstract protected function addGroupToGroup(string $outer, string $inner): void;
    abstract protected function addPaddingUsers(array $padding): void;
    abstract protected function finalize(): void;

    protected function env(string $key): string
    {
        $v = getenv($key);
        if ($v === false || $v === '') {
            throw new RuntimeException("Missing required env var: {$key}");
        }
        return $v;
    }

    protected function runCmd(array $cmd, ?string $stdin = null): string
    {
        $proc = proc_open($cmd, [
            0 => $stdin !== null ? ['pipe', 'r'] : ['file', '/dev/null', 'r'],
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ], $pipes);
        if (!is_resource($proc)) {
            throw new RuntimeException('proc_open failed: ' . implode(' ', $cmd));
        }
        if ($stdin !== null) {
            fwrite($pipes[0], $stdin);
            fclose($pipes[0]);
        }
        $out = stream_get_contents($pipes[1]);
        $err = stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $code = proc_close($proc);
        if ($code !== 0) {
            fwrite(STDERR, "\nCommand failed (exit {$code}): " . implode(' ', $cmd) . "\n");
            if ($stdin !== null) fwrite(STDERR, "stdin:\n{$stdin}\n");
            if ($out !== '')     fwrite(STDERR, "stdout:\n{$out}\n");
            if ($err !== '')     fwrite(STDERR, "stderr:\n{$err}\n");
            exit(1);
        }
        return $out;
    }

    protected function runCmdStatus(array $cmd): int
    {
        $proc = proc_open($cmd, [
            0 => ['file', '/dev/null', 'r'],
            1 => ['file', '/dev/null', 'w'],
            2 => ['file', '/dev/null', 'w'],
        ], $pipes);
        return is_resource($proc) ? proc_close($proc) : 1;
    }
}


class OpenLDAPProvisioner extends Provisioner
{
    private string $host;
    private int    $port;
    private string $bindDn;
    private string $bindPw;
    private string $peopleOu;
    private string $groupsOu;
    private int    $nextUidNumber = 1000;
    private int    $nextGidNumber = 5000;

    public function __construct(array $spec)
    {
        parent::__construct($spec);
        $this->host     = $this->env('OPENLDAP_HOST');
        $this->port     = (int) $this->env('OPENLDAP_PORT');
        $this->bindDn   = $this->env('OPENLDAP_BIND_DN');
        $this->bindPw   = $this->env('OPENLDAP_BIND_PW');
        $this->peopleOu = $this->env('OPENLDAP_PEOPLE_OU');
        $this->groupsOu = $this->env('OPENLDAP_GROUPS_OU');
    }

    protected function waitUntilReady(): void
    {
        echo "[OpenLDAPProvisioner] waiting for slapd...\n";
        $deadline = time() + 120;
        while (time() < $deadline) {
            if ($this->entryExists($this->env('OPENLDAP_BASE'))) {
                return;
            }
            usleep(500_000);
        }
        throw new RuntimeException("slapd did not become responsive within 120s");
    }

    protected function isAlreadyProvisioned(): bool
    {
        return $this->entryExists("uid=alice,{$this->peopleOu}");
    }

    protected function ensureRoot(): void
    {
        // osixia/openldap creates the dc=… root from LDAP_DOMAIN but no
        // sub-OUs; seed the two we plant entries under.
        foreach ([$this->peopleOu, $this->groupsOu] as $dn) {
            if ($this->entryExists($dn)) continue;
            [$attr, $val] = explode('=', explode(',', $dn, 2)[0], 2);
            $this->ldapAdd("dn: {$dn}\nobjectClass: organizationalUnit\n{$attr}: {$val}\n");
        }
    }

    protected function applyPasswordPolicy(): void
    {
        // Not modelled for slapd in this fixture.
    }

    protected function addGroup(array $g): void
    {
        $gid = ++$this->nextGidNumber;
        echo "  + group {$g['name']}\n";
        $this->ldapAdd(
            "dn: cn={$g['name']},{$this->groupsOu}\n"
            . "objectClass: posixGroup\n"
            . "cn: {$g['name']}\n"
            . "gidNumber: {$gid}\n"
        );
    }

    protected function addUser(array $u): void
    {
        $uidNumber = ++$this->nextUidNumber;
        $cn = "{$u['givenName']} {$u['sn']}";
        $ldif  = "dn: uid={$u['uid']},{$this->peopleOu}\n";
        $ldif .= "objectClass: inetOrgPerson\n";
        $ldif .= "objectClass: posixAccount\n";
        $ldif .= "uid: {$u['uid']}\n";
        $ldif .= "cn: {$cn}\n";
        $ldif .= "sn: {$u['sn']}\n";
        $ldif .= "givenName: {$u['givenName']}\n";
        if (isset($u['mail']))   $ldif .= "mail: {$u['mail']}\n";
        if (isset($u['mobile'])) $ldif .= "mobile: {$u['mobile']}\n";
        $ldif .= "uidNumber: {$uidNumber}\n";
        $ldif .= "gidNumber: {$uidNumber}\n";
        $ldif .= "homeDirectory: /home/{$u['uid']}\n";
        $ldif .= 'userPassword: ' . $this->sshaHash($u['password']) . "\n";
        echo "  + user {$u['uid']}\n";
        $this->ldapAdd($ldif);
    }

    protected function addUserToGroup(string $uid, string $group): void
    {
        $this->ldapModify(
            "dn: cn={$group},{$this->groupsOu}\n"
            . "changetype: modify\n"
            . "add: memberUid\n"
            . "memberUid: {$uid}\n"
        );
    }

    protected function addGroupToGroup(string $outer, string $inner): void
    {
        // posixGroup uses memberUid (RFC 2307) and doesn't model nested
        // groups. The spec carries 'contains' for AD's sake; on slapd
        // it's silently ignored.
    }

    protected function addPaddingUsers(array $p): void
    {
        echo "  + padding users (1..{$p['count']})\n";
        for ($i = 1; $i <= $p['count']; $i++) {
            $uid       = sprintf($p['uid_format'], $i);
            $given     = sprintf($p['givenName_format'], $i);
            $uidNumber = ++$this->nextUidNumber;
            $ldif  = "dn: uid={$uid},{$this->peopleOu}\n";
            $ldif .= "objectClass: inetOrgPerson\n";
            $ldif .= "objectClass: posixAccount\n";
            $ldif .= "uid: {$uid}\n";
            $ldif .= "cn: {$given} {$p['sn']}\n";
            $ldif .= "sn: {$p['sn']}\n";
            $ldif .= "givenName: {$given}\n";
            $ldif .= "uidNumber: {$uidNumber}\n";
            $ldif .= "gidNumber: {$uidNumber}\n";
            $ldif .= "homeDirectory: /home/{$uid}\n";
            $ldif .= 'userPassword: ' . $this->sshaHash($p['password']) . "\n";
            $this->ldapAdd($ldif);
            foreach ($p['memberships'] ?? [] as $m) {
                if ($i <= $m['first_n']) {
                    $this->addUserToGroup($uid, $m['group']);
                }
            }
            if ($i % 50 === 0) echo "    ...{$i}/{$p['count']}\n";
        }
    }

    protected function finalize(): void
    {
        // nothing
    }

    private function entryExists(string $dn): bool
    {
        return 0 === $this->runCmdStatus([
            'ldapsearch', '-x',
            '-H', "ldap://{$this->host}:{$this->port}",
            '-D', $this->bindDn, '-w', $this->bindPw,
            '-b', $dn, '-s', 'base', '-LLL', '(objectClass=*)', 'dn',
        ]);
    }

    private function ldapAdd(string $ldif): void
    {
        $this->runCmd([
            'ldapadd', '-x',
            '-H', "ldap://{$this->host}:{$this->port}",
            '-D', $this->bindDn, '-w', $this->bindPw,
        ], $ldif);
    }

    private function ldapModify(string $ldif): void
    {
        $this->runCmd([
            'ldapmodify', '-x',
            '-H', "ldap://{$this->host}:{$this->port}",
            '-D', $this->bindDn, '-w', $this->bindPw,
        ], $ldif);
    }

    private function sshaHash(string $pw): string
    {
        // Deterministic salt so the LDIF is reproducible.
        $salt = substr(hash('sha1', "ssha-salt:{$pw}", true), 0, 4);
        return '{SSHA}' . base64_encode(sha1($pw . $salt, true) . $salt);
    }
}


class SambaProvisioner extends Provisioner
{
    private string $container;
    private string $usersDn;
    private const LDB_PATH = '/var/lib/samba/private/sam.ldb';

    public function __construct(array $spec)
    {
        parent::__construct($spec);
        $this->container = $this->env('SAMBA_CONTAINER');
        $this->usersDn   = $this->env('SAMBA_USERS_DN');
    }

    protected function waitUntilReady(): void
    {
        echo "[SambaProvisioner] waiting for samba-tool (this is slow, samba self-provisions the domain first)...\n";
        $deadline = time() + 300;
        while (time() < $deadline) {
            $ok = 0 === $this->runCmdStatus([
                'docker', 'exec', $this->container,
                'samba-tool', 'user', 'list',
            ]);
            if ($ok) return;
            sleep(2);
        }
        throw new RuntimeException("samba did not become responsive within 300s");
    }

    protected function isAlreadyProvisioned(): bool
    {
        return 0 === $this->runCmdStatus([
            'docker', 'exec', $this->container,
            'samba-tool', 'user', 'show', 'alice',
        ]);
    }

    protected function ensureRoot(): void
    {
        // CN=Users,DC=… is created by samba's own provisioning at first
        // boot; nothing for us to seed.
    }

    protected function applyPasswordPolicy(): void
    {
        if (!isset($this->spec['password_policy']['max_pwd_age_days'])) {
            return;
        }
        $days = $this->spec['password_policy']['max_pwd_age_days'];
        $this->dockerExec([
            'samba-tool', 'domain', 'passwordsettings', 'set',
            "--max-pwd-age={$days}",
        ]);
    }

    protected function addGroup(array $g): void
    {
        echo "  + group {$g['name']}\n";
        $this->dockerExec(['samba-tool', 'group', 'add', $g['name']]);
    }

    protected function addUser(array $u): void
    {
        echo "  + user {$u['uid']}\n";
        $cmd = [
            'samba-tool', 'user', 'create', $u['uid'], $u['password'],
            '--given-name=' . $u['givenName'],
            '--surname='    . $u['sn'],
            '--use-username-as-cn',
        ];
        if (isset($u['mail'])) $cmd[] = '--mail-address=' . $u['mail'];
        $this->dockerExec($cmd);

        // Drop a single ldbmodify with all the post-create attribute
        // overrides; samba-tool exposes only a subset of attrs as flags.
        $attrs = ['displayName' => "{$u['givenName']} {$u['sn']}"];
        if (isset($u['mobile'])) {
            $attrs['mobile'] = $u['mobile'];
        }
        if (!empty($u['passwordNeverExpires'])) {
            // 512 NORMAL_ACCOUNT | 65536 DONT_EXPIRE_PASSWD = 66048
            $attrs['userAccountControl'] = '66048';
        }
        $this->ldbModify("CN={$u['uid']},{$this->usersDn}", $attrs);
    }

    protected function addUserToGroup(string $uid, string $group): void
    {
        $this->dockerExec(['samba-tool', 'group', 'addmembers', $group, $uid]);
    }

    protected function addGroupToGroup(string $outer, string $inner): void
    {
        $this->dockerExec(['samba-tool', 'group', 'addmembers', $outer, $inner]);
    }

    protected function addPaddingUsers(array $p): void
    {
        echo "  + padding users (1..{$p['count']}, this takes a minute)\n";
        for ($i = 1; $i <= $p['count']; $i++) {
            $uid   = sprintf($p['uid_format'], $i);
            $given = sprintf($p['givenName_format'], $i);
            $this->dockerExec([
                'samba-tool', 'user', 'create', $uid, $p['password'],
                "--given-name={$given}",
                "--surname={$p['sn']}",
                '--use-username-as-cn',
            ]);
            foreach ($p['memberships'] ?? [] as $m) {
                if ($i <= $m['first_n']) {
                    $this->dockerExec(['samba-tool', 'group', 'addmembers', $m['group'], $uid]);
                }
            }
            if ($i % 50 === 0) echo "    ...{$i}/{$p['count']}\n";
        }
    }

    protected function finalize(): void
    {
        echo "  + regenerate TLS cert with localhost SAN\n";
        $this->dockerExec(['/regen-tls.sh']);
    }

    private function dockerExec(array $cmd, ?string $stdin = null): void
    {
        $argv = ['docker', 'exec'];
        if ($stdin !== null) $argv[] = '-i';
        $argv[] = $this->container;
        array_push($argv, ...$cmd);
        $this->runCmd($argv, $stdin);
    }

    private function ldbModify(string $dn, array $attrs): void
    {
        $ldif = "dn: {$dn}\nchangetype: modify\n";
        $first = true;
        foreach ($attrs as $name => $value) {
            if (!$first) $ldif .= "-\n";
            $ldif .= "replace: {$name}\n{$name}: {$value}\n";
            $first = false;
        }
        $this->dockerExec(['ldbmodify', '-H', self::LDB_PATH], $ldif);
    }
}


// ---------------------------------------------------------------------------

$spec = json_decode(file_get_contents(SPEC_PATH), true, 512, JSON_THROW_ON_ERROR);

// Strip _comment keys (allowed in users.json for human notes)
$strip = function ($v) use (&$strip) {
    if (!is_array($v)) return $v;
    $out = [];
    foreach ($v as $k => $vv) {
        if (is_string($k) && str_starts_with($k, '_comment')) continue;
        $out[$k] = $strip($vv);
    }
    return $out;
};
$spec = $strip($spec);

(new OpenLDAPProvisioner($spec))->run();
(new SambaProvisioner($spec))->run();

echo "All backends provisioned.\n";
