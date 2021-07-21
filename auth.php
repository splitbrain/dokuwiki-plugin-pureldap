<?php

use dokuwiki\plugin\pureldap\classes\ADClient;
use dokuwiki\plugin\pureldap\classes\Client;

/**
 * DokuWiki Plugin pureldap (Auth Component)
 *
 * @license GPL 2 http://www.gnu.org/licenses/gpl-2.0.html
 * @author  Andreas Gohr <andi@splitbrain.org>
 */
class auth_plugin_pureldap extends DokuWiki_Auth_Plugin
{
    /** @var Client */
    protected $client;

    /**
     * Constructor.
     */
    public function __construct()
    {
        global $conf;
        parent::__construct(); // for compatibility

        // prepare the base client
        $this->loadConfig();
        $this->conf['admin_password'] = conf_decodeString($this->conf['admin_password']);
        $this->conf['defaultgroup'] = $conf['defaultgroup'];

        $this->client = new ADClient($this->conf); // FIXME decide class on config

        // set capabilities
        $this->cando['getUsers'] = true;
        $this->cando['getGroups'] = true;
        $this->cando['logout'] = !$this->client->getConf('sso');

        $this->success = true;
    }

    /** @inheritDoc */
    public function checkPass($user, $pass)
    {
        global $INPUT;

        // when SSO is enabled, the login is autotriggered and we simply trust the environment
        if (
            $this->client->getConf('sso') &&
            $INPUT->server->str('REMOTE_USER') !== '' &&
            $INPUT->server->str('REMOTE_USER') == $user
        ) {
            return true;
        }

        // use a separate client from the default one, because this is not a superuser bind
        $client = new ADClient($this->conf); // FIXME decide class on config
        return $client->authenticate($user, $pass);
    }

    /** @inheritDoc */
    public function getUserData($user, $requireGroups = true)
    {
        $info = $this->client->getCachedUser($user, $requireGroups);
        return $info ?: false;
    }

    /**
     * @inheritDoc
     */
    public function retrieveUsers($start = 0, $limit = 0, $filter = null)
    {
        return array_slice(
            $this->client->getFilteredUsers(
                $filter,
                Client::FILTER_CONTAINS
            ),
            $start,
            $limit);
    }

    /** @inheritDoc */
    public function retrieveGroups($start = 0, $limit = 0)
    {
        return array_slice($this->client->getCachedGroups(), $start, $limit);
    }

    /** @inheritDoc */
    public function isCaseSensitive()
    {
        return false;
    }

    /** @inheritDoc */
    public function cleanUser($user)
    {
        return $this->client->cleanUser($user);
    }

    /** @inheritDoc */
    public function cleanGroup($group)
    {
        return $group;
    }

    /** @inheritDoc */
    public function useSessionCache($user)
    {
        return true;
    }
}
