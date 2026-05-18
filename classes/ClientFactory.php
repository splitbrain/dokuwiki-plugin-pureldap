<?php

namespace dokuwiki\plugin\pureldap\classes;

/**
 * Picks the concrete {@see Client} implementation for the configured backend.
 *
 * Selection is keyed on the `directory_type` config option:
 *   `ad`   → {@see ADClient}: Active Directory specialisation
 *   `ldap` → {@see LDAPClient}: universal RFC 4511 / 2307 LDAP client
 */
class ClientFactory
{
    /**
     * @param array $config
     * @return Client
     * @throws \RuntimeException when directory_type is not recognised
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
                throw new \RuntimeException('Unknown directory_type "' . $type . '"');
        }
    }
}
