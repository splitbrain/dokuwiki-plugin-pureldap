<?php

namespace dokuwiki\plugin\pureldap\test;

use dokuwiki\plugin\pureldap\classes\ADClient;

/**
 * General tests for the pureldap plugin
 *
 * @group plugin_pureldap
 * @group plugins
 */
class ADClientTest extends \DokuWikiTest
{
    /**
     * Create a client with default settings
     *
     * Optionally allows to override configs.
     *
     * All tests assume to be running against https://github.com/splitbrain/vagrant-active-directory
     *
     * @param array $conf
     * @return ADClient
     */
    protected function getClient($conf = [])
    {
        return new ADClient(
            array_merge(
                [
                    'base_dn' => 'DC=example,DC=local',
                    'suffix' => 'example.local',
                    'servers' => ['localhost'],
                    'port' => 7636,
                    'admin_username' => 'vagrant',
                    'admin_password' => 'vagrant',
                    'encryption' => 'ssl',
                    'validate' => 'self',
                    'attributes' => ['mobile'],
                ],
                $conf
            )
        );
    }

    /**
     * Check user fetching
     */
    public function testGetUser()
    {
        $expect = [
            'user' => 'a.legrand',
            'name' => 'Amerigo Legrand',
            'mail' => 'a.legrand@example.com',
            'dn' => 'CN=Amerigo Legrand,CN=Users,DC=example,DC=local',
            'grps' => [
                'beta',
                'domain users',
                'gamma nested',
                'user',
            ],
            'mobile' => '+63 (483) 526-8809',
        ];

        $client = $this->getClient();
        $user = $client->getUser('a.legrand@example.local');
        $this->assertSame($expect, $user);

        // access should work without the domain, too
        $user = $client->getUser('a.legrand');
        $this->assertSame($expect, $user);

        // access should be case Insensitive
        $user = $client->getUser('A.LeGrand');
        $this->assertSame($expect, $user);
    }

    /**
     * Check recursive groups
     *
     */
    public function testGetUserRecursiveGroups()
    {
        // User m.albro is member of 'gamma nested', which is in turn part of 'beta'
        // thus the user should be part of both groups
        $expect = [
            'beta',
            'domain users',
            'gamma nested',
            'user',
        ];

        $client = $this->getClient(['recursivegroups' => 1]);
        $user = $client->getUser('m.albro@example.local');
        $this->assertSame($expect, $user['grps']);
    }

    /**
     * Check getting all groups
     */
    public function testGetGroups()
    {
        // to check paging, we set a super small page size
        $client = $this->getClient(['page_size' => 2]);

        $groups = $client->getGroups();
        $this->assertGreaterThan(3, count($groups));
        $this->assertContains('alpha', $groups);
        $this->assertContains('beta', $groups);
        $this->assertContains('gamma nested', $groups);
        $this->assertContains('domain users', $groups);
    }

    /**
     * Check getting filtered groups
     */
    public function testGetGroupsFiltered()
    {
        // to check paging, we set a super small page size
        $client = $this->getClient(['page_size' => 2]);

        $groups = $client->getGroups('alpha', ADClient::FILTER_EQUAL);
        $this->assertCount(1, $groups);
        $this->assertSame(['alpha'], array_values($groups));
    }

    public function testGetFilteredUsers()
    {
        // to check paging, we set a super small page size
        $client = $this->getClient(['page_size' => 2]);

        $users = $client->getFilteredUsers(['grps' => 'alpha'], ADClient::FILTER_EQUAL);
        $this->assertGreaterThan(20, count($users));
        $this->assertLessThan(150, count($users));

        $this->assertArrayHasKey('a.blaskett', $users, 'This user should be in alpha');
        $this->assertArrayNotHasKey('a.legrand', $users, 'This user is not in alpha');

        $users = $client->getFilteredUsers(['grps' => 'alpha', 'name' => 'Andras'], ADClient::FILTER_STARTSWITH);
        $this->assertCount(1, $users);

        // a group with a space
        $users = $client->getFilteredUsers(['grps' => 'gamma nested'], ADClient::FILTER_EQUAL);
        $this->assertArrayHasKey('m.mcnevin', $users, 'This user should be in Gamma Nested');
    }

    public function testGetFilteredUsersRecursiveGroups()
    {
        // User m.albro is member of 'gamma nested', which is in turn part of 'beta'
        // thus the user should be part of both groups

        $client = $this->getClient(['recursivegroups' => 1]);

        $users = $client->getFilteredUsers(['grps' => 'beta'], ADClient::FILTER_EQUAL);
        $this->assertArrayHasKey('m.albro', $users, 'user should be in beta');

        $users = $client->getFilteredUsers(['grps' => 'gamma nested'], ADClient::FILTER_EQUAL);
        $this->assertArrayHasKey('m.albro', $users, 'user should be in gamma nested');
    }

    public function testGetDomainUsers()
    {
        $client = $this->getClient();
        $users = $client->getFilteredUsers(['grps' => 'domain users'], ADClient::FILTER_EQUAL);
        $this->assertGreaterThan(250, count($users));

        $users = $client->getFilteredUsers(['grps' => 'domain'], ADClient::FILTER_STARTSWITH);
        $this->assertGreaterThan(250, count($users));
    }

    /**
     * Check that we can resolve nested groups (users are checked in @see test_getUserRecursiveGroups already)
     */
//    public function test_resolveRecursiveMembership() {
//        $client = $this->getClient();
//
//        /** @var \FreeDSx\Ldap\Search\Paging $result */
//        $result = $this->callInaccessibleMethod(
//            $client,
//            'resolveRecursiveMembership',
//            [['CN=beta,CN=Users,DC=example,DC=local'], 'memberOf']
//        );
//        $entries = $result->getEntries();
//        $this->assertEquals(1, $entries->count());
//        $this->assertEquals('Gamma Nested', ($entries->first()->get('name')->getValues())[0]);
//    }
}
