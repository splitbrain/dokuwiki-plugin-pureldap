<?php

namespace dokuwiki\plugin\pureldap\test;

/**
 * Base class for tests that require a live LDAP or AD server.
 *
 * Tests opt in by setting the HOST_ENV environment variable to point at
 * the server they want to use. That can be the docker-compose fixture
 * in _test/docker-compose.yml (localhost), or any other reachable
 * LDAP/AD server — including a real one in a developer's environment.
 *
 * If the host env var is unset, the test is skipped so the same suite
 * runs cleanly under the standard dokuwiki/github-action workflow
 * without a server present.
 *
 * Subclasses override the constants to point at the env vars they want
 * and the default port for their server flavor.
 */
abstract class LDAPTestCase extends \DokuWikiTest
{
    protected const HOST_ENV = 'LDAP_TEST_HOST';
    protected const PORT_ENV = 'LDAP_TEST_PORT';
    protected const DEFAULT_PORT = 389;

    /** @var string */
    protected $ldapHost;
    /** @var int */
    protected $ldapPort;

    public function setUp(): void
    {
        $host = getenv(static::HOST_ENV);
        if (!$host) {
            $this->markTestSkipped('Set ' . static::HOST_ENV . ' to run this test (docker fixture or real server)');
        }
        $this->ldapHost = $host;
        $this->ldapPort = (int)(getenv(static::PORT_ENV) ?: static::DEFAULT_PORT);
        parent::setUp();
    }
}
