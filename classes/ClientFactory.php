<?php

namespace dokuwiki\plugin\pureldap\classes;

/**
 * Picks the concrete {@see Client} implementation for the configured backend.
 */
class ClientFactory
{
    /**
     * @param array $config
     * @return Client
     */
    public static function create(array $config)
    {
        return new ADClient($config);
    }
}
