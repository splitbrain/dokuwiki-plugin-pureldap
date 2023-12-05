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
                    'port' => 7389, // SSL: 7636
                    'admin_username' => 'vagrant',
                    'admin_password' => 'vagrant',
                    'encryption' => 'tls',
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
            'expires' => false,
            'mobile' => '+63 (483) 526-8809',
        ];

        $client = $this->getClient();
        $user = $client->getUser('a.legrand@example.local');

        $this->assertGreaterThan(mktime(0,0,0,6,1,2023), $user['lastpwd'], 'lastpwd should be a timestamp');
        unset($user['lastpwd']); // we don't know the exact value, so we remove it for the comparison
        $this->assertSame($expect, $user);

        // access should work without the domain, too
        $user = $client->getUser('a.legrand');
        unset($user['lastpwd']);
        $this->assertSame($expect, $user);

        // access should be case Insensitive
        $user = $client->getUser('A.LeGrand');
        unset($user['lastpwd']);
        $this->assertSame($expect, $user);
    }

    public function testGetLongUser()
    {
        $client = $this->getClient();
        $user = $client->getUser('averylongusernamethatisverylong');
        $this->assertIsArray($user);
        $this->assertEquals('averylongusernamethatisverylong', $user['user']);


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

    public function testSetPassword()
    {
        $client = $this->getClient();
        // password is set as administrator
        $this->assertTrue($client->setPassword('x.guiu', 'Shibol eTH876?!'), 'Password set as admin');

        // login as user
        $this->assertTrue($client->authenticate('x.guiu', 'Shibol eTH876?!'), 'Password works');

        // set new pass as user
        $this->assertTrue($client->setPassword('x.guiu', 'Fully New 1234??', 'Shibol eTH876?!'), 'Password as user');

        // login as user with new password
        $this->assertTrue($client->authenticate('x.guiu', 'Fully New 1234??'), 'New Password works');

        // use new client for admin connection, and reset password back
        $client = $this->getClient();
        $this->assertTrue($client->setPassword('x.guiu', 'Foo_b_ar123!'), 'Password set back as admin');
    }

    public function testMaxPasswordAge()
    {
        $client = $this->getClient();
        $maxAge = $client->getMaxPasswordAge(false);

        // convert to days
        $maxAge = $maxAge / 60 / 60 / 24;

        $this->assertEquals(42, $maxAge, 'Default password age is 42 days');
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
