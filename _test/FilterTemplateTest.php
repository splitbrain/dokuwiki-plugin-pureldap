<?php

namespace dokuwiki\plugin\pureldap\test;

use dokuwiki\plugin\pureldap\classes\FilterTemplate;
use DokuWikiTest;

/**
 * Unit tests for FilterTemplate.
 *
 * No LDAP server is required for these.
 *
 * @group plugin_pureldap
 * @group plugins
 */
class FilterTemplateTest extends DokuWikiTest
{
    public function testNoPlaceholders()
    {
        $this->assertSame('(objectClass=user)', FilterTemplate::substitute('(objectClass=user)', []));
    }

    public function testSinglePlaceholder()
    {
        $this->assertSame(
            '(uid=alice)',
            FilterTemplate::substitute('(uid=%{user})', ['user' => 'alice'])
        );
    }

    public function testMultiplePlaceholders()
    {
        $template = '(&(uid=%{user})(memberOf=cn=%{group},ou=Groups,dc=example,dc=org))';
        $expected = '(&(uid=alice)(memberOf=cn=admins,ou=Groups,dc=example,dc=org))';
        $this->assertSame(
            $expected,
            FilterTemplate::substitute($template, ['user' => 'alice', 'group' => 'admins'])
        );
    }

    public function testUnknownPlaceholderLeftAlone()
    {
        $this->assertSame(
            '(uid=%{user})',
            FilterTemplate::substitute('(uid=%{user})', ['other' => 'x'])
        );
    }

    public function testArrayValueTakesFirstElement()
    {
        $this->assertSame(
            '(uid=alice)',
            FilterTemplate::substitute('(uid=%{user})', ['user' => ['alice', 'bob']])
        );
    }

    /**
     * The five characters LDAP filters require escaped (RFC 4515 §3):
     * NUL, `*`, `(`, `)`, `\`. Plus other control bytes for safety.
     */
    public function testFilterEscapeSpecials()
    {
        $this->assertSame('al\28ice\29', FilterTemplate::filterEscape('al(ice)'));
        $this->assertSame('a\2ab', FilterTemplate::filterEscape('a*b'));
        $this->assertSame('a\5cb', FilterTemplate::filterEscape('a\\b'));
        $this->assertSame('a\00b', FilterTemplate::filterEscape("a\x00b"));
    }

    public function testFilterEscapePassThroughForPlainText()
    {
        $this->assertSame('alice.smith@example.org', FilterTemplate::filterEscape('alice.smith@example.org'));
    }

    public function testSubstitutionEscapesValues()
    {
        // a malicious user trying to inject filter syntax should be neutralised
        $this->assertSame(
            '(uid=alice\29\28memberOf=cn=admins)',
            FilterTemplate::substitute('(uid=%{user})', ['user' => 'alice)(memberOf=cn=admins'])
        );
    }
}
