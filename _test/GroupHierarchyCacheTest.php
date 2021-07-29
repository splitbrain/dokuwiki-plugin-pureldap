<?php

namespace dokuwiki\plugin\pureldap\test;

use dokuwiki\plugin\pureldap\classes\ADClient;
use dokuwiki\plugin\pureldap\classes\GroupHierarchyCache;
use DokuWikiTest;

/**
 * tests for the pureldap plugin
 *
 * @group plugin_pureldap
 * @group plugins
 */
class GroupHierarchyCacheTest extends DokuWikiTest
{

    /**
     * Return an initialized GroupHierarchyCache
     *
     * Creates a client with default settings. Optionally allows to override configs.
     *
     * All tests assume to be running against https://github.com/splitbrain/vagrant-active-directory
     *
     * @param array $conf
     * @return GroupHierarchyCache|null
     */
    protected function getClient($conf = [])
    {
        $client = new ADClient(
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

        return $client->getGroupHierarchyCache();
    }

    public function testGetGroupList()
    {
        $ghc = $this->getClient();
        $list = $this->callInaccessibleMethod($ghc, 'getGroupList', []);

        $this->assertGreaterThan(20, $list);
        $this->assertArrayHasKey('CN=Gamma Nested,CN=Users,DC=example,DC=local', $list);
        $this->assertArrayHasKey('parents', $list['CN=Gamma Nested,CN=Users,DC=example,DC=local']);
        $this->assertArrayHasKey('children', $list['CN=Gamma Nested,CN=Users,DC=example,DC=local']);
    }

    public function testGetParents()
    {
        $ghc = $this->getClient();
        $this->assertEquals(
            [
                'CN=Gamma Nested,CN=Users,DC=example,DC=local',
                'CN=beta,CN=Users,DC=example,DC=local',
            ],
            $ghc->getParents('CN=omega nested,CN=Users,DC=example,DC=local')
        );
    }

    public function testGetChildren()
    {
        $ghc = $this->getClient();
        $this->assertEquals(
            [
                'CN=Gamma Nested,CN=Users,DC=example,DC=local',
                'CN=omega nested,CN=Users,DC=example,DC=local',
            ],
            $ghc->getChildren('CN=beta,CN=Users,DC=example,DC=local')
        );
    }

}
