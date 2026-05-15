<?php

namespace dokuwiki\plugin\pureldap\test;

require_once __DIR__ . '/RequiresAD.php';

/**
 * @group plugin_pureldap
 * @group plugins
 */
class AuthTest extends \DokuWikiTest {

    use RequiresAD;

    public function setUp(): void
    {
        $this->skipIfNoAD('localhost', 7636);
        parent::setUp();

        global $conf;
        $conf['auth'] = 'pureldap';
        $conf['plugin']['pureldap']['base_dn'] = 'dc=example,dc=com';
        $conf['plugin']['pureldap']['suffix'] = 'example.com';
        $conf['plugin']['pureldap']['servers'] = ['localhost'];
        $conf['plugin']['pureldap']['port'] = 7636;
        $conf['plugin']['pureldap']['admin_username'] = 'Administrator';
        $conf['plugin']['pureldap']['admin_password'] = 'Foo_b_ar123!';
        $conf['plugin']['pureldap']['encryption'] = 'ssl';
        $conf['plugin']['pureldap']['validate'] = 'self';
    }

    public function testADlogin() {
        $auth = new \auth_plugin_pureldap();
        $this->assertTrue($auth->checkPass('a.legrand', 'Foo_b_ar123!'));
        $this->assertFalse($auth->checkPass('a.legrand', 'wrong password'));
    }

    public function testADLongUserLogin()
    {
        $auth = new \auth_plugin_pureldap();

        // sam account name
        $this->assertTrue($auth->checkPass('longlong', 'Foo_b_ar123!'));
        $this->assertFalse($auth->checkPass('longlong', 'wrong password'));

        $this->assertTrue($auth->checkPass('averylongusernamethatisverylong', 'Foo_b_ar123!'));
        $this->assertFalse($auth->checkPass('averylongusernamethatisverylong', 'wrong password'));
    }

    public function testADloginSSO() {
        global $conf;
        $conf['plugin']['pureldap']['sso'] = 1;

        $_SERVER['REMOTE_USER'] = 'a.legrand';

        $auth = new \auth_plugin_pureldap();
        $this->assertTrue($auth->checkPass('a.legrand', 'sso-only'));
    }
}
