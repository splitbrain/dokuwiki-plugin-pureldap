#!/usr/bin/env php
<?php

/**
 * Apply the shared fixture spec (users.json) to one LDAP backend.
 *
 *   php provision.php --backend openldap
 *   php provision.php --backend samba
 *
 * Same control flow either way:
 *
 *     foreach ($groups as $g)      addGroup($g, $backend);
 *     foreach ($users as $u)       addUser($u, $backend);
 *     foreach ($memberships as $m) addMembership($m, $backend);
 *
 * The per-entity backend handlers shell out to native CLI tools — never
 * to a PHP LDAP client. That keeps the test data path independent of
 * FreeDSx, which is the library we're actually testing.
 *
 *   openldap →  ldapadd / ldapmodify  (over LDAP from the host)
 *   samba    →  docker exec → samba-tool / ldbmodify  (on the local sam.ldb)
 *
 * The TLS-cert regen for Samba happens at the end via the small in-
 * container script mounted by docker-compose.samba.yml.
 *
 * The script is idempotent: if the canonical probe user already exists,
 * it exits without doing work, so a re-invocation against a populated
 * container is a no-op.
 */

const SPEC_PATH = __DIR__ . '/users.json';

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

$opts = getopt('', ['backend:', 'spec::', 'force']);
$backend = $opts['backend'] ?? null;
if (!in_array($backend, ['openldap', 'samba'], true)) {
    fwrite(STDERR, "Usage: provision.php --backend openldap|samba [--spec path] [--force]\n");
    exit(2);
}
$specPath = $opts['spec'] ?? SPEC_PATH;
$force    = isset($opts['force']);

$spec = json_decode(file_get_contents($specPath), true, 512, JSON_THROW_ON_ERROR);
$spec = stripCommentKeys($spec);
$ctx  = $spec['domains'][$backend];

// ---------------------------------------------------------------------------
// Driver
// ---------------------------------------------------------------------------

waitForBackend($backend, $ctx);

if (!$force && probeUser($ctx['probe_user'], $backend, $ctx)) {
    echo "Fixture already provisioned ({$ctx['probe_user']} present). Skipping.\n";
    exit(0);
}

if ($backend === 'openldap') {
    // osixia/openldap creates the dc=… root from env vars but no sub-OUs.
    // The first user/group add would fail with "no such object" against
    // an absent parent, so seed the containers we declared in the spec.
    ensureContainer($ctx['people_ou'], $ctx);
    ensureContainer($ctx['groups_ou'], $ctx);
}

if (isset($spec['password_policy'][$backend])) {
    applyPasswordPolicy($spec['password_policy'][$backend], $backend, $ctx);
}

foreach (forBackend($spec['groups'], $backend) as $g) {
    addGroup($g, $backend, $ctx);
}
foreach (forBackend($spec['groups'], $backend) as $g) {
    foreach ($g[$backend]['memberGroups'] ?? [] as $inner) {
        addGroupToGroup($g['name'], $inner, $backend, $ctx);
    }
}
foreach (forBackend($spec['users'], $backend) as $u) {
    addUser($u, $backend, $ctx);
}
foreach (forBackend($spec['users'], $backend) as $u) {
    foreach ($u['memberOf'] ?? [] as $group) {
        addUserToGroup($u['uid'], $group, $backend, $ctx);
    }
}

if (isset($spec['padding']) && in_array($backend, $spec['padding']['backends'], true)) {
    addPaddingUsers($spec['padding'], $backend, $ctx);
}

if ($backend === 'samba') {
    echo "Regenerating Samba TLS cert with localhost SAN...\n";
    runDockerExec($ctx['container'], ['/regen-tls.sh']);
}

verify($backend, $ctx);
echo "Provisioning complete: $backend\n";

// ---------------------------------------------------------------------------
// Per-entity dispatch
// ---------------------------------------------------------------------------

function addGroup(array $g, string $backend, array $ctx): void
{
    echo "  + group  {$g['name']}\n";
    if ($backend === 'openldap') {
        $ldif = "dn: cn={$g['name']},{$ctx['groups_ou']}\n"
              . "objectClass: posixGroup\n"
              . "cn: {$g['name']}\n"
              . "gidNumber: {$g['openldap']['gid']}\n";
        ldapAdd($ldif, $ctx);
    } else {
        runDockerExec($ctx['container'], ['samba-tool', 'group', 'add', $g['name']]);
    }
}

function addUser(array $u, string $backend, array $ctx): void
{
    echo "  + user   {$u['uid']}\n";
    if ($backend === 'openldap') {
        $cn = $u['cn'] ?? "{$u['givenName']} {$u['sn']}";
        $ldif  = "dn: uid={$u['uid']},{$ctx['people_ou']}\n";
        $ldif .= "objectClass: inetOrgPerson\n";
        $ldif .= "objectClass: posixAccount\n";
        $ldif .= "uid: {$u['uid']}\n";
        $ldif .= "cn: {$cn}\n";
        $ldif .= "sn: {$u['sn']}\n";
        $ldif .= "mail: {$u['mail']}\n";
        $ldif .= "uidNumber: {$u['openldap']['uidNumber']}\n";
        $ldif .= "gidNumber: {$u['openldap']['gidNumber']}\n";
        $ldif .= "homeDirectory: {$u['openldap']['homeDirectory']}\n";
        $ldif .= 'userPassword: ' . sshaHash($u['password']) . "\n";
        if (isset($u['mobile'])) {
            $ldif .= "mobile: {$u['mobile']}\n";
        }
        ldapAdd($ldif, $ctx);
        return;
    }

    $cmd = [
        'samba-tool', 'user', 'create', $u['uid'], $u['password'],
        '--given-name=' . $u['givenName'],
        '--surname='    . $u['sn'],
        '--use-username-as-cn',
    ];
    if (isset($u['mail'])) {
        $cmd[] = '--mail-address=' . $u['mail'];
    }
    runDockerExec($ctx['container'], $cmd);

    $dn = "CN={$u['uid']},{$ctx['users_dn']}";
    $attrs = ['displayName' => $u['cn'] ?? "{$u['givenName']} {$u['sn']}"];
    if (isset($u['mobile'])) {
        $attrs['mobile'] = $u['mobile'];
    }
    if (isset($u['samba']['userAccountControl'])) {
        $attrs['userAccountControl'] = (string) $u['samba']['userAccountControl'];
    }
    ldbModify($ctx, $dn, $attrs);
}

function addUserToGroup(string $uid, string $group, string $backend, array $ctx): void
{
    if ($backend === 'openldap') {
        $ldif = "dn: cn={$group},{$ctx['groups_ou']}\n"
              . "changetype: modify\n"
              . "add: memberUid\n"
              . "memberUid: {$uid}\n";
        ldapModify($ldif, $ctx);
    } else {
        runDockerExec($ctx['container'], [
            'samba-tool', 'group', 'addmembers', $group, $uid,
        ]);
    }
}

function addGroupToGroup(string $outer, string $inner, string $backend, array $ctx): void
{
    if ($backend !== 'samba') {
        throw new RuntimeException("Group nesting is only modelled for samba");
    }
    runDockerExec($ctx['container'], [
        'samba-tool', 'group', 'addmembers', $outer, $inner,
    ]);
}

function addPaddingUsers(array $padding, string $backend, array $ctx): void
{
    $count = $padding['count'];
    echo "  + padding users (1..{$count}, this takes a minute)\n";
    for ($i = 1; $i <= $count; $i++) {
        $uid   = sprintf($padding['uid_format'], $i);
        $given = sprintf($padding['givenName_format'], $i);
        if ($backend === 'openldap') {
            // Padding only configured for samba in users.json; if it ever
            // expands, this branch will need uidNumber/gidNumber allocation.
            throw new RuntimeException("Padding for openldap not implemented");
        }
        runDockerExec($ctx['container'], [
            'samba-tool', 'user', 'create', $uid, $padding['password'],
            '--given-name=' . $given,
            '--surname='    . $padding['sn'],
            '--use-username-as-cn',
        ]);
        foreach ($padding['memberships'] ?? [] as $m) {
            if ($i <= $m['first_n']) {
                runDockerExec($ctx['container'], [
                    'samba-tool', 'group', 'addmembers', $m['group'], $uid,
                ]);
            }
        }
        if ($i % 50 === 0) {
            echo "    ...{$i}/{$count}\n";
        }
    }
}

function applyPasswordPolicy(array $policy, string $backend, array $ctx): void
{
    if ($backend !== 'samba') return;
    if (isset($policy['max_pwd_age_days'])) {
        runDockerExec($ctx['container'], [
            'samba-tool', 'domain', 'passwordsettings', 'set',
            '--max-pwd-age=' . $policy['max_pwd_age_days'],
        ]);
    }
}

// ---------------------------------------------------------------------------
// Backend invocation helpers
// ---------------------------------------------------------------------------

function ensureContainer(string $dn, array $ctx): void
{
    if (entryExists($dn, $ctx)) {
        return;
    }
    [$rdnAttr, $rdnValue] = explode('=', explode(',', $dn, 2)[0], 2);
    echo "  + container {$dn}\n";
    ldapAdd("dn: {$dn}\nobjectClass: organizationalUnit\n{$rdnAttr}: {$rdnValue}\n", $ctx);
}

function entryExists(string $dn, array $ctx): bool
{
    $proc = proc_open(
        ['ldapsearch', '-x',
         '-H', "ldap://{$ctx['host']}:{$ctx['port']}",
         '-D', $ctx['bind_dn'],
         '-w', $ctx['bind_pw'],
         '-b', $dn,
         '-s', 'base', '-LLL', '(objectClass=*)', 'dn'],
        [0 => ['file', '/dev/null', 'r'],
         1 => ['file', '/dev/null', 'w'],
         2 => ['file', '/dev/null', 'w']],
        $pipes
    );
    return is_resource($proc) && proc_close($proc) === 0;
}

function ldapAdd(string $ldif, array $ctx): void
{
    run(
        ['ldapadd', '-x',
         '-H', "ldap://{$ctx['host']}:{$ctx['port']}",
         '-D', $ctx['bind_dn'],
         '-w', $ctx['bind_pw']],
        $ldif
    );
}

function ldapModify(string $ldif, array $ctx): void
{
    run(
        ['ldapmodify', '-x',
         '-H', "ldap://{$ctx['host']}:{$ctx['port']}",
         '-D', $ctx['bind_dn'],
         '-w', $ctx['bind_pw']],
        $ldif
    );
}

function ldbModify(array $ctx, string $dn, array $attrs): void
{
    $ldif = "dn: {$dn}\nchangetype: modify\n";
    $first = true;
    foreach ($attrs as $name => $value) {
        if (!$first) $ldif .= "-\n";
        $ldif .= "replace: {$name}\n{$name}: {$value}\n";
        $first = false;
    }
    runDockerExec($ctx['container'], ['ldbmodify', '-H', $ctx['ldb_path']], $ldif);
}

function runDockerExec(string $container, array $cmd, ?string $stdin = null): void
{
    $needs_stdin = $stdin !== null;
    $argv = ['docker', 'exec'];
    if ($needs_stdin) $argv[] = '-i';
    $argv[] = $container;
    array_push($argv, ...$cmd);
    run($argv, $stdin);
}

function run(array $cmd, ?string $stdin = null): string
{
    $descriptors = [
        0 => $stdin !== null ? ['pipe', 'r'] : ['file', '/dev/null', 'r'],
        1 => ['pipe', 'w'],
        2 => ['pipe', 'w'],
    ];
    $proc = proc_open($cmd, $descriptors, $pipes);
    if (!is_resource($proc)) {
        throw new RuntimeException('Failed to spawn: ' . implode(' ', $cmd));
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

// ---------------------------------------------------------------------------
// Lifecycle: wait, probe, verify
// ---------------------------------------------------------------------------

function waitForBackend(string $backend, array $ctx): void
{
    echo "Waiting for {$backend} to become responsive...\n";
    $deadline = time() + ($backend === 'samba' ? 240 : 120);
    while (time() < $deadline) {
        if (backendReady($backend, $ctx)) {
            echo "  ready.\n";
            return;
        }
        usleep(500_000);
    }
    fwrite(STDERR, "::error::{$backend} did not become responsive in time\n");
    exit(1);
}

function backendReady(string $backend, array $ctx): bool
{
    if ($backend === 'openldap') {
        $proc = proc_open(
            ['ldapsearch', '-x',
             '-H', "ldap://{$ctx['host']}:{$ctx['port']}",
             '-D', $ctx['bind_dn'],
             '-w', $ctx['bind_pw'],
             '-b', $ctx['base'],
             '-s', 'base', '-LLL', '(objectClass=*)', 'dn'],
            [0 => ['file', '/dev/null', 'r'],
             1 => ['file', '/dev/null', 'w'],
             2 => ['file', '/dev/null', 'w']],
            $pipes
        );
        return is_resource($proc) && proc_close($proc) === 0;
    }
    $proc = proc_open(
        ['docker', 'exec', $ctx['container'], 'samba-tool', 'user', 'list'],
        [0 => ['file', '/dev/null', 'r'],
         1 => ['file', '/dev/null', 'w'],
         2 => ['file', '/dev/null', 'w']],
        $pipes
    );
    return is_resource($proc) && proc_close($proc) === 0;
}

function probeUser(string $uid, string $backend, array $ctx): bool
{
    if ($backend === 'openldap') {
        $proc = proc_open(
            ['ldapsearch', '-x',
             '-H', "ldap://{$ctx['host']}:{$ctx['port']}",
             '-D', $ctx['bind_dn'],
             '-w', $ctx['bind_pw'],
             '-b', $ctx['people_ou'],
             '-LLL', "(uid={$uid})", 'uid'],
            [0 => ['file', '/dev/null', 'r'],
             1 => ['pipe', 'w'],
             2 => ['file', '/dev/null', 'w']],
            $pipes
        );
        if (!is_resource($proc)) return false;
        $out = stream_get_contents($pipes[1]);
        fclose($pipes[1]);
        proc_close($proc);
        return str_contains($out, "uid: {$uid}");
    }
    $proc = proc_open(
        ['docker', 'exec', $ctx['container'], 'samba-tool', 'user', 'show', $uid],
        [0 => ['file', '/dev/null', 'r'],
         1 => ['file', '/dev/null', 'w'],
         2 => ['file', '/dev/null', 'w']],
        $pipes
    );
    return is_resource($proc) && proc_close($proc) === 0;
}

function verify(string $backend, array $ctx): void
{
    if (!probeUser($ctx['probe_user'], $backend, $ctx)) {
        fwrite(STDERR, "::error::Post-provision probe failed: {$ctx['probe_user']} not found in {$backend}\n");
        exit(1);
    }
    echo "Verified: {$ctx['probe_user']} present in {$backend}\n";
}

// ---------------------------------------------------------------------------
// Misc helpers
// ---------------------------------------------------------------------------

function forBackend(array $entities, string $backend): array
{
    return array_values(array_filter(
        $entities,
        fn($e) => in_array($backend, $e['backends'] ?? [], true)
    ));
}

function stripCommentKeys($v)
{
    if (is_array($v)) {
        $out = [];
        foreach ($v as $k => $vv) {
            if (is_string($k) && str_starts_with($k, '_comment')) continue;
            $out[$k] = stripCommentKeys($vv);
        }
        return $out;
    }
    return $v;
}

function sshaHash(string $password): string
{
    // Deterministic salt so re-rendering is reproducible. The salt
    // is embedded in the hash, so slapd verifies it correctly
    // regardless of how it was generated.
    $salt = substr(hash('sha1', "ssha-salt:{$password}", true), 0, 4);
    return '{SSHA}' . base64_encode(sha1($password . $salt, true) . $salt);
}
