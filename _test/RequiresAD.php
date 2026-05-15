<?php

namespace dokuwiki\plugin\pureldap\test;

/**
 * Skip helper for tests that require a live Active Directory server.
 *
 * The AD-backed tests assume the vagrant-active-directory fixture is up
 * (https://github.com/splitbrain/vagrant-active-directory). When the
 * fixture isn't reachable we skip cleanly instead of failing the run, so
 * the same suite can be executed by the standard dokuwiki/github-action
 * workflow without an AD server present.
 */
trait RequiresAD
{
    protected function skipIfNoAD(string $host = 'localhost', int $port = 7389): void
    {
        $sock = @fsockopen($host, $port, $errno, $errstr, 1);
        if (!$sock) {
            $this->markTestSkipped("AD test server not reachable on $host:$port");
        }
        fclose($sock);
    }
}
