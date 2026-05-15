<?php

namespace dokuwiki\plugin\pureldap\test\integration;

use dokuwiki\plugin\pureldap\classes\Client;
use dokuwiki\plugin\pureldap\classes\LDAPClient;
use DokuWikiTest;

/**
 * Integration tests for the generic LDAPClient.
 *
 * Requires a running OpenLDAP server with the fixture data in
 * _test/fixtures/openldap/bootstrap.ldif. A compose file
 * (_test/docker-compose.openldap.yml) provisions one with the right
 * schema, sample users, and memberOf overlay.
 *
 * The whole suite is skipped when LDAP_TEST_HOST is unset, so CI without
 * the docker fixture stays green.
 *
 * @group plugin_pureldap
 * @group plugin_pureldap_integration
 * @group plugins
 */
class LDAPClientTest extends DokuWikiTest
{
    /** @var string */
    protected $host;
    /** @var int */
    protected $port;

    public function setUp(): void
    {
        $host = getenv('LDAP_TEST_HOST');
        if (!$host) {
            $this->markTestSkipped('Set LDAP_TEST_HOST to run LDAPClient integration tests');
        }
        $this->host = $host;
        $this->port = (int)(getenv('LDAP_TEST_PORT') ?: 389);
        parent::setUp();
    }

    /**
     * @param array $extra config overrides
     * @return LDAPClient
     */
    protected function getClient(array $extra = [])
    {
        return new LDAPClient(array_merge([
            'directory_type' => 'ldap',
            'base_dn' => 'dc=example,dc=org',
            'servers' => [$this->host],
            'port' => $this->port,
            'encryption' => 'none',
            'admin_username' => 'cn=admin,dc=example,dc=org',
            'admin_password' => 'adminpass',
            'usertree' => 'ou=People,dc=example,dc=org',
            'grouptree' => 'ou=Groups,dc=example,dc=org',
            'userkey' => 'uid',
            'groupkey' => 'cn',
            'namekey' => 'cn',
            'mailkey' => 'mail',
            'userClass' => 'posixAccount',
            'groupClass' => 'posixGroup',
        ], $extra));
    }

    public function testGetUserViaGrouptreeStrategy()
    {
        $client = $this->getClient([
            'userfilter' => '(&(uid=%{user})(objectClass=posixAccount))',
            'groupfilter' => '(&(objectClass=posixGroup)(memberUid=%{user}))',
            'group_strategy' => 'grouptree',
        ]);

        $user = $client->getUser('alice');
        $this->assertIsArray($user);
        $this->assertSame('alice', $user['user']);
        $this->assertSame('Alice Example', $user['name']);
        $this->assertSame('alice@example.org', $user['mail']);
        $this->assertContains('devs', $user['grps']);
        $this->assertContains('admins', $user['grps']);
        $this->assertNotContains('ops', $user['grps']);
    }

    public function testGetUserViaMemberOfStrategy()
    {
        // Requires the memberOf overlay; skip if the fixture didn't enable it.
        $client = $this->getClient(['group_strategy' => 'memberof']);
        $user = $client->getUser('alice');
        $this->assertIsArray($user);
        if (empty($user['grps']) || $user['grps'] === [$client->getConf('defaultgroup')]) {
            $this->markTestSkipped('memberOf overlay not enabled on the fixture');
        }
        $this->assertContains('devs', $user['grps']);
    }

    public function testAuthenticateSearchThenBind()
    {
        $client = $this->getClient();
        $this->assertTrue($client->authenticate('alice', 'password'));
    }

    public function testAuthenticateDirectBindTemplate()
    {
        $client = $this->getClient(['binddn' => 'uid=%{user},ou=People,dc=example,dc=org']);
        $this->assertTrue($client->authenticate('alice', 'password'));
    }

    public function testRetrieveGroups()
    {
        $client = $this->getClient();
        $groups = $client->getGroups();
        $names = array_values($groups);
        $this->assertContains('devs', $names);
        $this->assertContains('ops', $names);
        $this->assertContains('admins', $names);
    }

    public function testGetFilteredUsersByGroup()
    {
        $client = $this->getClient([
            'userfilter' => '(&(uid=%{user})(objectClass=posixAccount))',
            'groupfilter' => '(&(objectClass=posixGroup)(memberUid=%{user}))',
            'group_strategy' => 'grouptree',
        ]);

        $users = $client->getFilteredUsers(
            ['grps' => 'admins'],
            Client::FILTER_EQUAL
        );
        $this->assertArrayHasKey('alice', $users);
        $this->assertArrayNotHasKey('bob', $users);
    }
}
