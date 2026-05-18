<?php

namespace dokuwiki\plugin\pureldap\test;

use dokuwiki\plugin\pureldap\classes\Client;
use dokuwiki\plugin\pureldap\classes\LDAPClient;

/**
 * Integration tests for the generic LDAPClient.
 *
 * Requires the OpenLDAP service from _test/docker-compose.yml to be up
 * (`docker compose up -d --wait`). The whole suite is skipped when
 * LDAP_TEST_HOST is unset, so CI without the docker fixture stays green.
 *
 * Assertions are authored against the shared users.csv / groups.csv
 * fixture data. OpenLDAP stores groups flat (parent column ignored),
 * so a user's `grps` reflects only their direct memberships.
 *
 * @group plugin_pureldap
 * @group plugin_pureldap_ldap
 * @group plugins
 */
class LDAPClientTest extends LDAPTestCase
{
    /**
     * @param array $extra config overrides
     * @return LDAPClient
     */
    protected function getClient(array $extra = [])
    {
        return new LDAPClient(array_merge([
            'directory_type' => 'ldap',
            'base_dn' => 'dc=example,dc=com',
            'servers' => [$this->ldapHost],
            'port' => $this->ldapPort,
            'encryption' => 'none',
            'admin_username' => 'cn=admin,dc=example,dc=com',
            'admin_password' => 'Foo_b_ar123!',
            'usertree' => 'ou=People,dc=example,dc=com',
            'grouptree' => 'ou=Groups,dc=example,dc=com',
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

        $user = $client->getUser('m.mcnevin');
        $this->assertIsArray($user);
        $this->assertSame('m.mcnevin', $user['user']);
        $this->assertSame('Marcela McNevin', $user['name']);
        $this->assertSame('m.mcnevin@example.com', $user['mail']);
        $this->assertContains('beta', $user['grps']);
        $this->assertContains('gamma nested', $user['grps']);
        $this->assertContains('omega nested', $user['grps']);
        $this->assertNotContains('alpha', $user['grps']);
    }

    public function testGetUserViaMemberOfStrategy()
    {
        // Requires the memberOf overlay; skip if the fixture didn't enable it.
        $client = $this->getClient(['group_strategy' => 'memberof']);
        $user = $client->getUser('m.mcnevin');
        $this->assertIsArray($user);
        if (empty($user['grps']) || $user['grps'] === ['user']) {
            $this->markTestSkipped('memberOf overlay not enabled on the fixture');
        }
        $this->assertContains('beta', $user['grps']);
    }

    public function testAuthenticateSearchThenBind()
    {
        $client = $this->getClient();
        $this->assertTrue($client->authenticate('a.legrand', 'Foo_b_ar123!'));
    }

    public function testAuthenticateDirectBindTemplate()
    {
        $client = $this->getClient(['binddn' => 'uid=%{user},ou=People,dc=example,dc=com']);
        $this->assertTrue($client->authenticate('a.legrand', 'Foo_b_ar123!'));
    }

    public function testRetrieveGroups()
    {
        $client = $this->getClient();
        $groups = $client->getGroups();
        $names = array_values($groups);
        $this->assertContains('alpha', $names);
        $this->assertContains('beta', $names);
        $this->assertContains('gamma nested', $names);
        $this->assertContains('omega nested', $names);
    }

    public function testGetFilteredUsersByGroup()
    {
        $client = $this->getClient([
            'userfilter' => '(&(uid=%{user})(objectClass=posixAccount))',
            'groupfilter' => '(&(objectClass=posixGroup)(memberUid=%{user}))',
            'group_strategy' => 'grouptree',
        ]);

        $users = $client->getFilteredUsers(
            ['grps' => 'alpha'],
            Client::FILTER_EQUAL
        );
        $this->assertArrayHasKey('m.barten', $users);
        $this->assertArrayNotHasKey('m.mcnevin', $users);
    }
}
