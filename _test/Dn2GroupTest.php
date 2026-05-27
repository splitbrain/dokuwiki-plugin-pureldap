<?php

namespace dokuwiki\plugin\pureldap\test;

use dokuwiki\plugin\pureldap\classes\LDAPClient;
use DokuWikiTest;
use ReflectionClass;

/**
 * Unit tests for LDAPClient::dn2group(). No LDAP server required; the
 * instance is built via reflection so the parent constructor (which
 * would open a real LDAP connection) is skipped.
 *
 * @group plugin_pureldap
 * @group plugin_pureldap_unit
 * @group plugins
 */
class Dn2GroupTest extends DokuWikiTest
{
    public function dnProvider(): array
    {
        return [
            'plain CN' => ['CN=admins,OU=groups,DC=example,DC=com', 'admins'],
            'lowercased' => ['cn=Admins,dc=example,dc=com', 'admins'],
            'uid first rdn' => ['uid=alice,ou=people,dc=example,dc=com', 'alice'],
            'escaped comma in value' => ['CN=Smith\\, John,OU=groups,DC=example,DC=com', 'smith, john'],
            'hex-escaped comma' => ['CN=Smith\\2C John,OU=groups,DC=example,DC=com', 'smith, john'],
            'escaped plus' => ['CN=A\\+B,DC=example,DC=com', 'a+b'],
            'escaped backslash' => ['CN=foo\\\\bar,DC=example,DC=com', 'foo\\bar'],
            'multi-valued RDN keeps first attribute value' => ['CN=admins+OU=ops,DC=example,DC=com', 'admins'],
            'no equals (degenerate)' => ['admins', 'admins'],
        ];
    }

    /**
     * @dataProvider dnProvider
     */
    public function testDn2Group(string $dn, string $expected): void
    {
        $client = (new ReflectionClass(LDAPClient::class))->newInstanceWithoutConstructor();
        $this->assertSame($expected, self::callInaccessibleMethod($client, 'dn2group', [$dn]));
    }
}
