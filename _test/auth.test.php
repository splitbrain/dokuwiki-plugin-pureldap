<?php

namespace dokuwiki\plugin\pureldap\test;

/**
 * @group plugin_pureldap
 * @group plugins
 */
class authTest extends \DokuWikiTest {

    public function setUp(): void
    {
        parent::setUp();

        global $conf;
        $conf['auth'] = 'pureldap';
        $conf['plugin']['pureldap']['base_dn'] = 'DC=example,DC=local';
        $conf['plugin']['pureldap']['suffix'] = 'example.local';
        $conf['plugin']['pureldap']['servers'] = ['localhost'];
        $conf['plugin']['pureldap']['port'] = 7636;
        $conf['plugin']['pureldap']['admin_username'] = 'vagrant';
        $conf['plugin']['pureldap']['admin_password'] = 'vagrant';
        $conf['plugin']['pureldap']['encryption'] = 'ssl';
        $conf['plugin']['pureldap']['validate'] = 'self';
    }

    public function test_ADlogin() {
        $auth = new \auth_plugin_pureldap();
        $this->assertTrue($auth->checkPass('a.legrand', 'Foo_b_ar123!'));
        $this->assertFalse($auth->checkPass('a.legrand', 'wrong password'));
    }

    public function test_ADloginSSO() {
        global $conf;
        $conf['plugin']['pureldap']['sso'] = 1;

        $_SERVER['REMOTE_USER'] = 'a.legrand';

        $auth = new \auth_plugin_pureldap();
        $this->assertTrue($auth->checkPass('a.legrand', 'sso-only'));
    }
}
