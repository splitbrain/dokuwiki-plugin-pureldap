<?php

use dokuwiki\plugin\pureldap\classes\ADClient;

/**
 * General tests for the pureldap plugin
 *
 * @group plugin_pureldap
 * @group plugins
 */
class adcliebt_plugin_pureldap_test extends DokuWikiTest
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
                    'servers' => ['127.0.0.1'],
                    'port' => 7389,
                    'admin_username' => 'vagrant@example.local',
                    'admin_password' => 'vagrant',
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
        $client = $this->getClient();
        $user = $client->getUser('a.legrand@example.local');

        $this->assertSame([
            'user' => 'a.legrand@example.local',
            'name' => 'Amerigo Legrand',
            'mail' => 'a.legrand@example.com',
            'dn' => 'CN=Amerigo Legrand,CN=Users,DC=example,DC=local',
            'grps' => [
                'user',
                'gamma nested',
                'beta',
                'Domain Users',
            ],
        ], $user);
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
    }

    /**
     * Check getting filtered groups
     */
    public function test_getGroupsFiltered()
    {
        // to check paging, we set a super small page size
        $client = $this->getClient(['page_size' => 2]);

        $groups = $client->getGroups('alpha', 'equal');
        $this->assertCount(1, $groups);
        $this->assertSame(['alpha'], array_values($groups));
    }

    public function test_getFilteredUsers()
    {
        // to check paging, we set a super small page size
        $client = $this->getClient(['page_size' => 2]);

        $users = $client->getFilteredUsers(['grps' => 'alpha'], 'equal');
        $this->assertGreaterThan(20, count($users));
        $this->assertLessThan(150, count($users));

        $users = $client->getFilteredUsers(['grps' => 'alpha', 'name' => 'Andras'], 'startswith');
        $this->assertCount(1, $users);
    }
}
