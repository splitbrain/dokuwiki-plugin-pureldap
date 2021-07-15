<?php

use dokuwiki\plugin\pureldap\classes\ADClient;

/**
 * General tests for the pureldap plugin
 *
 * @group plugin_pureldap
 * @group plugins
 */
class adclient_plugin_pureldap_test extends DokuWikiTest
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
    public function test_getUser()
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
     * Check getting all groups
     */
    public function test_getGroups()
    {
        // to check paging, we set a super small page size
        $client = $this->getClient(['page_size' => 2]);

        $groups = $client->getGroups();
        $this->assertGreaterThan(3, count($groups));
        $this->assertContains('alpha', $groups);
        $this->assertContains('beta', $groups);
        $this->assertContains('domain users', $groups);
    }

    /**
     * Check getting filtered groups
     */
    public function test_getGroupsFiltered()
    {
        // to check paging, we set a super small page size
        $client = $this->getClient(['page_size' => 2]);

        $groups = $client->getGroups('alpha', ADClient::FILTER_EQUAL);
        $this->assertCount(1, $groups);
        $this->assertSame(['alpha'], array_values($groups));
    }

    public function test_getFilteredUsers()
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

    public function test_getDomainUsers()
    {
        $client = $this->getClient();
        $users = $client->getFilteredUsers(['grps' => 'domain users'], ADClient::FILTER_EQUAL);
        $this->assertGreaterThan(250, count($users));

        $users = $client->getFilteredUsers(['grps' => 'domain'], ADClient::FILTER_STARTSWITH);
        $this->assertGreaterThan(250, count($users));
    }
}
