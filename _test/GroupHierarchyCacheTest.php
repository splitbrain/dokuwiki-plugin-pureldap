<?php

namespace dokuwiki\plugin\pureldap\test;

use dokuwiki\plugin\pureldap\classes\ADClient;
use dokuwiki\plugin\pureldap\classes\GroupHierarchyCache;

/**
 * tests for the pureldap plugin
 *
 * @group plugin_pureldap
 * @group plugin_pureldap_ad
 * @group plugins
 */
class GroupHierarchyCacheTest extends LDAPTestCase
{
    protected const HOST_ENV = 'AD_TEST_HOST';
    protected const PORT_ENV = 'AD_TEST_PORT_SSL';
    protected const DEFAULT_PORT = 7636;

    /**
     * Return an initialized GroupHierarchyCache
     *
     * Creates a client with default settings. Optionally allows to override configs.
     *
     * All tests assume to be running against the compose fixture in
     * _test/docker-compose.yml.
     *
     * @param array $conf
     * @return GroupHierarchyCache|null
     */
    protected function getClient($conf = [])
    {
        $client = new ADClient(
            array_merge(
                [
                    'base_dn' => 'dc=example,dc=com',
                    'suffix' => 'example.com',
                    'servers' => [$this->ldapHost],
                    'port' => $this->ldapPort,
                    'admin_username' => 'Administrator',
                    'admin_password' => 'Foo_b_ar123!',
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
        $this->assertArrayHasKey('CN=Gamma Nested,CN=Users,DC=example,DC=com', $list);
        $this->assertArrayHasKey('parents', $list['CN=Gamma Nested,CN=Users,DC=example,DC=com']);
        $this->assertArrayHasKey('children', $list['CN=Gamma Nested,CN=Users,DC=example,DC=com']);
    }

    public function testGetParents()
    {
        $ghc = $this->getClient();
        $this->assertEquals(
            [
                'CN=Gamma Nested,CN=Users,DC=example,DC=com',
                'CN=beta,CN=Users,DC=example,DC=com',
            ],
            $ghc->getParents('CN=omega nested,CN=Users,DC=example,DC=com')
        );
    }

    public function testGetChildren()
    {
        $ghc = $this->getClient();
        $this->assertEquals(
            [
                'CN=Gamma Nested,CN=Users,DC=example,DC=com',
                'CN=omega nested,CN=Users,DC=example,DC=com',
            ],
            $ghc->getChildren('CN=beta,CN=Users,DC=example,DC=com')
        );
    }

}
