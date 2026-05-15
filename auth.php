<?php

use dokuwiki\Extension\AuthPlugin;
use dokuwiki\plugin\pureldap\classes\Client;
use dokuwiki\plugin\pureldap\classes\ClientFactory;

/**
 * DokuWiki Plugin pureldap (Auth Component)
 *
 * @license GPL 2 http://www.gnu.org/licenses/gpl-2.0.html
 * @author  Andreas Gohr <andi@splitbrain.org>
 */
class auth_plugin_pureldap extends AuthPlugin
{
    /** @var Client */
    public $client;

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

        $this->client = ClientFactory::create($this->conf);

        // set capabilities
        $this->cando['getUsers'] = true;
        $this->cando['getGroups'] = true;
        $this->cando['logout'] = !$this->client->getConf('sso');
        $this->cando['modPass'] = $this->client->canModPass();


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

        // try to bind with the user credentials, client will stay authenticated as user
        $this->client = ClientFactory::create($this->conf);
        try {
            $this->client->authenticate($user, $pass);
            return true;
        } catch (\Exception $e) {
            $this->renderBindError($e);
            return false;
        }
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
            $limit
        );
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

    /**
     * Support password changing
     * @inheritDoc
     */
    public function modifyUser($user, $changes)
    {
        if (empty($changes['pass'])) {
            $this->client->error('Only password changes are supported', __FILE__, __LINE__);
            return false;
        }

        global $INPUT;
        return $this->client->setPassword($user, $changes['pass'], $INPUT->str('oldpass', null, true));
    }

    /**
     * Ask the client to translate a bind exception and render the resulting
     * message (with an optional password-reset link).
     *
     * @param \Exception $e
     * @return void
     */
    protected function renderBindError(\Exception $e)
    {
        $info = $this->client->translateBindException($e);
        if ($info === null) return;

        $message = $this->getLang($info['key']) ?: $info['key'];

        if (!empty($info['allowReset']) && $this->canDo('modPass')) {
            $link = '<a href="' . wl('start', ['do' => 'resendpwd']) . '" class="pureldap-reset-link">' .
                $this->getLang('pass_reset') . '</a>';
            $message .= ' ' . $link;
        }

        msg($message, -1);
    }
}
