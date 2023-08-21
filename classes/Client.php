<?php

namespace dokuwiki\plugin\pureldap\classes;

use dokuwiki\ErrorHandler;
use dokuwiki\Logger;
use dokuwiki\Utf8\Clean;
use dokuwiki\Utf8\PhpString;
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Exception\BindException;
use FreeDSx\Ldap\Exception\ConnectionException;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\LdapClient;

require_once __DIR__ . '/../vendor/autoload.php';

abstract class Client
{
    const FILTER_EQUAL = 'equal';
    const FILTER_CONTAINS = 'contains';
    const FILTER_STARTSWITH = 'startsWith';
    const FILTER_ENDSWITH = 'endsWith';

    /** @var array the configuration */
    protected $config;

    /** @var LdapClient */
    protected $ldap;

    /** @var bool|string is this client authenticated already? Contains username if yes */
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
        $this->prepareSSO();
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
        // ensure we have the default keys
        /** @var array $conf */
        include __DIR__ . '/../conf/default.php';
        $defaults = $conf;
        $defaults['defaultgroup'] = 'user'; // we expect this to be passed from global conf

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

        $config['suffix'] = ltrim(PhpString::strtolower($config['suffix']), '@');
        $config['primarygroup'] = $this->cleanGroup($config['primarygroup']);

        return $config;
    }

    /**
     * Extract user info from environment for SSO
     */
    protected function prepareSSO()
    {
        global $INPUT;

        if (!$this->config['sso']) return;
        if ($INPUT->server->str('REMOTE_USER') === '') return;

        $user = $INPUT->server->str('REMOTE_USER');

        // make sure the right encoding is used
        if ($this->config['sso_charset']) {
            if (function_exists('iconv')) {
                $user = iconv($this->config['sso_charset'], 'UTF-8', $user);
            } elseif (function_exists('mb_convert_encoding')) {
                $user = mb_convert_encoding($user, 'UTF-8', $this->config['sso_charset']);
            }
        } elseif (!Clean::isUtf8($user)) {
            $user = utf8_encode($user);
        }
        $user = $this->cleanUser($user);

        // Prepare SSO

        // trust the incoming user
        $INPUT->server->set('REMOTE_USER', $user);

        // we need to simulate a login
        if (empty($_COOKIE[DOKU_COOKIE])) {
            $INPUT->set('u', $user);
            $INPUT->set('p', 'sso_only');
        }
    }

    /**
     * Access to the config values
     *
     * Because the client class does configuration cleanup, the auth class should access
     * config values through the client
     *
     * @param string $key
     * @return mixed returns null on missing config
     */
    public function getConf($key)
    {
        if (!isset($this->config[$key])) return null;
        return $this->config[$key];
    }

    /**
     * Authenticate as admin if not authenticated yet
     */
    public function autoAuth()
    {
        if ($this->isAuthenticated) return true;

        $user = $this->prepareBindUser($this->config['admin_username']);
        $ok = $this->authenticate($user, $this->config['admin_password']);
        if (!$ok) {
            $this->error('Automatic bind failed. Probably wrong user/password.', __FILE__, __LINE__);
        }
        return $ok;
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
        $user = $this->prepareBindUser($user);
        $this->isAuthenticated = false;

        if (!$this->ldap->isConnected() && $this->config['encryption'] === 'tls') {
            try {
                $this->ldap->startTls();
            } catch (ConnectionException|OperationException $e) {
                $this->fatal($e);
                return false;
            }
        }

        try {
            $this->ldap->bind($user, $pass);
        } catch (BindException $e) {
            $this->debug("Bind for $user failed: " . $e->getMessage(), $e->getFile(), $e->getLine());
            return false;
        } catch (ConnectionException|OperationException $e) {
            $this->fatal($e);
            return false;
        }

        $this->isAuthenticated = $user;
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
        if ($this->config['usefscache']) {
            $cachename = getCacheName($username, '.pureldap-user');
            $cachetime = @filemtime($cachename);
            if ($cachetime && (time() - $cachetime) < $conf['auth_security_timeout']) {
                $this->userCache[$username] = json_decode(file_get_contents($cachename), true);
                if (!$fetchgroups || is_array($this->userCache[$username]['grps'])) {
                    return $this->userCache[$username];
                }
            }
        }

        // fetch fresh data
        $info = $this->getUser($username, $fetchgroups);

        // store in cache
        if ($this->config['usefscache'] && $info !== null) {
            $this->userCache[$username] = $info;
            /** @noinspection PhpUndefinedVariableInspection We know that cachename is defined */
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
     * Set a new password for a user
     *
     * @param string $username
     * @param string $newpass
     * @param string $oldpass Needed for self-service password change in AD
     * @return bool
     */
    abstract public function setPassword($username, $newpass, $oldpass = null);

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
    abstract public function getGroups($match = null, $filtermethod = self::FILTER_EQUAL);

    /**
     * Clean the user name for use in DokuWiki
     *
     * @param string $user
     * @return string
     */
    abstract public function cleanUser($user);

    /**
     * Clean the group name for use in DokuWiki
     *
     * @param string $group
     * @return string
     */
    abstract public function cleanGroup($group);

    /**
     * Inheriting classes may want to manipulate the user before binding
     *
     * @param string $user
     * @return string
     */
    protected function prepareBindUser($user)
    {
        return $user;
    }

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
     * Get the attributes that should be fetched for a user
     *
     * Can be extended in sub classes
     *
     * @return Attribute[]
     */
    protected function userAttributes()
    {
        // defaults
        $attr = [
            new Attribute('dn'),
            new Attribute('displayName'),
            new Attribute('mail'),
        ];
        // additionals
        foreach ($this->config['attributes'] as $attribute) {
            $attr[] = new Attribute($attribute);
        }
        return $attr;
    }

    /**
     * Get the maximum age a password may have before it needs to be changed
     *
     * @return int 0 if no maximum age is set
     */
    public function getMaxPasswordAge() {
        return 0;
    }

    /**
     * Handle fatal exceptions
     *
     * @param \Exception $e
     */
    protected function fatal(\Exception $e)
    {
        ErrorHandler::logException($e);

        if (defined('DOKU_UNITTEST')) {
            throw new \RuntimeException('', 0, $e);
        }

        msg('[pureldap] ' . hsc($e->getMessage()), -1);
    }

    /**
     * Handle error output
     *
     * @param string $msg
     * @param string $file
     * @param int $line
     */
    public function error($msg, $file, $line)
    {
        Logger::error('[pureldap] ' . $msg, '', $file, $line);

        if (defined('DOKU_UNITTEST')) {
            throw new \RuntimeException($msg . ' at ' . $file . ':' . $line);
        }

        msg('[pureldap] ' . hsc($msg), -1);
    }

    /**
     * Handle debug output
     *
     * @param string $msg
     * @param string $file
     * @param int $line
     */
    public function debug($msg, $file, $line)
    {
        global $conf;

        Logger::debug('[pureldap] ' . $msg, '', $file, $line);

        if ($conf['allowdebug']) {
            msg('[pureldap] ' . hsc($msg) . ' at ' . $file . ':' . $line);
        }
    }
}
