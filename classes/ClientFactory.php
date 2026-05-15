<?php

namespace dokuwiki\plugin\pureldap\classes;

use dokuwiki\Logger;

/**
 * Picks the concrete {@see Client} implementation for the configured backend.
 *
 * Selection is keyed on the `directory_type` config option:
 *   `ad`   → {@see ADClient}: Active Directory specialisation
 *   `ldap` → {@see LDAPClient}: universal RFC 4511 / 2307 LDAP client
 *
 * Unknown values fall back to `ad` with a logged error so an unattended
 * upgrade can't silently break a working AD deployment.
 */
class ClientFactory
{
    /**
     * @param array $config
     * @return Client
     */
    public static function create(array $config)
    {
        $type = $config['directory_type'] ?? 'ad';
        switch ($type) {
            case 'ldap':
                return new LDAPClient($config);
            case 'ad':
                return new ADClient($config);
            default:
                Logger::error('[pureldap] Unknown directory_type "' . $type . '", falling back to ad');
                return new ADClient($config);
        }
    }
}
