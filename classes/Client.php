<?php

namespace dokuwiki\plugin\pureldap\classes;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Exception\BindException;
use FreeDSx\Ldap\Exception\ConnectionException;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\LdapClient;

require_once __DIR__ . '/../vendor/autoload.php';

abstract class Client
{
    /** @var array the configuration */
    protected $config;

    /** @var LdapClient */
    protected $ldap;

    /** @var bool is this client authenticated already? */
    protected $isAuthenticated = false;

    /** @var array cached user info */
    protected $userCache = [];

    /**
     * Client constructor.
     * @param array $config
     */
    public function __construct($config)
    {
        $this->config = $this->prepareConfig($config);
        $this->ldap = new LdapClient($this->config);
    }

    /**
     * Setup sane config defaults
     *
     * @param array $config
     * @return array
     */
    protected function prepareConfig($config)
    {
        $defaults = [
            'defaultgroup' => 'user', // we expect this to be passed from global conf
            'use_tls' => false,
            'use_ssl' => false,
            'port' => '',
            'admin_username' => '',
            'admin_password' => '',
        ];

        $config = array_merge($defaults, $config);

        // default port depends on SSL setting
        if (!$config['port']) {
            $config['port'] = $config['use_ssl'] ? 636 : 389;
        }

        return $config;
    }

    /**
     * Authenticate as admin
     */
    public function autoAuth()
    {
        if ($this->isAuthenticated) return true;
        return $this->authenticate($this->config['admin_username'], $this->config['admin_password']);
    }

    /**
     * Authenticates a given user. This client will remain authenticated
     *
     * @param string $user
     * @param string $pass
     * @return bool was the authentication successful?
     */
    public function authenticate($user, $pass)
    {
        if ($this->config['use_tls']) {
            try {
                $this->ldap->startTls();
            } catch (OperationException $e) {
                $this->debug($e);
            }
        }

        try {
            $this->ldap->bind($user, $pass);
        } catch (BindException $e) {
            return false;
        } catch (ConnectionException $e) {
            $this->debug($e);
            return false;
        } catch (OperationException $e) {
            $this->debug($e);
            return false;
        }

        $this->isAuthenticated = true;
        return true;
    }

    /**
     * Get info for a single user, use cache if available
     *
     * @param string $username
     * @param bool $fetchgroups Are groups needed?
     * @return array|null
     */
    public function getCachedUser($username, $fetchgroups = true)
    {
        if (isset($this->userCache[$username])) {
            if (!$fetchgroups || is_array($this->userCache[$username]['grps'])) {
                return $this->userCache[$username];
            }
        }

        // fetch fresh data
        $info = $this->getUser($username, $fetchgroups);

        // store in cache
        if ($info !== null) {
            $this->userCache[$username] = $info;
        }

        return $info;
    }

    /**
     * Fetch a single user
     *
     * @param string $username
     * @param bool $fetchgroups Shall groups be fetched, too?
     * @return null|array
     */
    abstract public function getUser($username, $fetchgroups = true);

    /**
     * Helper method to get the first value of the given attribute
     *
     * The given attribute may be null, an empty string is returned then
     *
     * @param Attribute|null $attribute
     * @return string
     */
    protected function attr2str($attribute) {
        if($attribute !== null) {
            return $attribute->firstValue();
        }
        return '';
    }


    /**
     * Handle debugging
     *
     * @param \Exception $e
     * @todo more output, better handling if it should be shown or what
     */
    protected function debug(\Exception $e)
    {
        if(defined('DOKU_UNITTEST')) {
            throw $e;
        }

        msg($e->getMessage(), -1);
    }
}
