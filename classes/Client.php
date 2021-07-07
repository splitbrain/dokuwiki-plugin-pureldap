<?php

namespace dokuwiki\plugin\pureldap\classes;

use dokuwiki\Utf8\PhpString;
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

    /** @var array cached group list */
    protected $groupCache = [];

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
            'domain' => '',
            'port' => '',
            'encryption' => false,
            'admin_username' => '',
            'admin_password' => '',
            'page_size' => 1000,
            'use_ssl' => false,
            'validate' => 'strict',
        ];

        $config = array_merge($defaults, $config);

        // default port depends on SSL setting
        if (!$config['port']) {
            $config['port'] = ($config['encryption'] === 'ssl') ? 636 : 389;
        }

        // set ssl parameters
        $config['use_ssl'] = ($config['encryption'] === 'ssl');
        if ($config['validate'] === 'none') {
            $config['ssl_validate_cert'] = false;
        } elseif ($config['validate'] === 'self') {
            $config['ssl_allow_self_signed'] = true;
        }

        $config['domain'] = PhpString::strtolower($config['domain']);

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
     * @noinspection PhpRedundantCatchClauseInspection
     */
    public function authenticate($user, $pass)
    {
        $user = $this->qualifiedUser($user);

        if ($this->config['encryption'] === 'tls') {
            try {
                $this->ldap->startTls();
            } catch (OperationException $e) {
                $this->fatal($e);
            }
        }

        try {
            $this->ldap->bind($user, $pass);
        } catch (BindException $e) {
            return false;
        } catch (ConnectionException $e) {
            $this->fatal($e);
            return false;
        } catch (OperationException $e) {
            $this->fatal($e);
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
        global $conf;

        // memory cache first
        if (isset($this->userCache[$username])) {
            if (!$fetchgroups || is_array($this->userCache[$username]['grps'])) {
                return $this->userCache[$username];
            }
        }

        // disk cache second
        $cachename = getCacheName($username, '.pureldap-user');
        $cachetime = @filemtime($cachename);
        if ($cachetime && (time() - $cachetime) < $conf['auth_security_timeout']) {
            $this->userCache[$username] = json_decode(file_get_contents($cachename), true);
            if (!$fetchgroups || is_array($this->userCache[$username]['grps'])) {
                return $this->userCache[$username];
            }
        }

        // fetch fresh data
        $info = $this->getUser($username, $fetchgroups);

        // store in cache
        if ($info !== null) {
            $this->userCache[$username] = $info;
            file_put_contents($cachename, json_encode($info));
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
     * Return a list of all available groups, use cache if available
     *
     * @return string[]
     */
    public function getCachedGroups()
    {
        if (empty($this->groupCache)) {
            $this->groupCache = $this->getGroups();
        }

        return $this->groupCache;
    }

    /**
     * Return a list of all available groups
     *
     * Optionally filter the list
     *
     * @param null|string $match Filter for this, null for all groups
     * @param string $filtermethod How to match the groups
     * @return string[]
     */
    abstract public function getGroups($match = null, $filtermethod = 'equal');

    /**
     * Construst the fully qualified name to identify a user
     *
     * @param string $username
     * @return string
     */
    abstract public function qualifiedUser($username);

    /**
     * Simplify the username if possible
     *
     * @param string $username
     * @return string
     */
    abstract public function simpleUser($username);

    /**
     * Helper method to get the first value of the given attribute
     *
     * The given attribute may be null, an empty string is returned then
     *
     * @param Attribute|null $attribute
     * @return string
     */
    protected function attr2str($attribute)
    {
        if ($attribute !== null) {
            return $attribute->firstValue();
        }
        return '';
    }

    /**
     * Handle fatal exceptions
     *
     * @param \Exception $e
     */
    protected function fatal(\Exception $e)
    {
        if (defined('DOKU_UNITTEST')) {
            throw new \RuntimeException('', 0, $e);
        }
        msg('[pureldap] ' . hsc($e->getMessage()) . ' at ' . $e->getFile() . ':' . $e->getLine(), -1);
    }

    /**
     * Handle debug output
     *
     * @param string $msg
     * @param string $file
     * @param int $line
     */
    protected function debug($msg, $file, $line)
    {
        msg('[pureldap] ' . hsc($msg) . ' at ' . $file . ':' . $line, 0);
    }
}
