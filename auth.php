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

        $this->cando['getUsers'] = true;
        $this->cando['getGroups'] = true;

        // prepare the base client
        $this->loadConfig();
        $this->conf['admin_password'] = conf_decodeString($this->conf['admin_password']);
        $this->conf['defaultgroup'] = $conf['defaultgroup'];

        $this->client = new ADClient($this->conf); // FIXME decide class on config
        $this->success = true;
    }


    /**
     * Log off the current user [ OPTIONAL ]
     */
    // public function logOff()
    // {
    // }

    /**
     * Do all authentication [ OPTIONAL ]
     *
     * @param string $user Username
     * @param string $pass Cleartext Password
     * @param bool $sticky Cookie should not expire
     *
     * @return  bool             true on successful auth
     */
    //public function trustExternal($user, $pass, $sticky = false)
    //{
    /* some example:

    global $USERINFO;
    global $conf;
    $sticky ? $sticky = true : $sticky = false; //sanity check

    // do the checking here

    // set the globals if authed
    $USERINFO['name'] = 'FIXME';
    $USERINFO['mail'] = 'FIXME';
    $USERINFO['grps'] = array('FIXME');
    $_SERVER['REMOTE_USER'] = $user;
    $_SESSION[DOKU_COOKIE]['auth']['user'] = $user;
    $_SESSION[DOKU_COOKIE]['auth']['pass'] = $pass;
    $_SESSION[DOKU_COOKIE]['auth']['info'] = $USERINFO;
    return true;

    */
    //}

    /** @inheritDoc */
    public function checkPass($user, $pass)
    {
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
     * Create a new User [implement only where required/possible]
     *
     * Returns false if the user already exists, null when an error
     * occurred and true if everything went well.
     *
     * The new user HAS TO be added to the default group by this
     * function!
     *
     * Set addUser capability when implemented
     *
     * @param string $user
     * @param string $pass
     * @param string $name
     * @param string $mail
     * @param null|array $grps
     *
     * @return bool|null
     */
    //public function createUser($user, $pass, $name, $mail, $grps = null)
    //{
    // FIXME implement
    //    return null;
    //}

    /**
     * Modify user data [implement only where required/possible]
     *
     * Set the mod* capabilities according to the implemented features
     *
     * @param string $user nick of the user to be changed
     * @param array $changes array of field/value pairs to be changed (password will be clear text)
     *
     * @return  bool
     */
    //public function modifyUser($user, $changes)
    //{
    // FIXME implement
    //    return false;
    //}

    /**
     * Delete one or more users [implement only where required/possible]
     *
     * Set delUser capability when implemented
     *
     * @param array $users
     *
     * @return  int    number of users deleted
     */
    //public function deleteUsers($users)
    //{
    // FIXME implement
    //    return false;
    //}

    /** @inheritDoc */
    public function retrieveUsers($start = 0, $limit = 0, $filter = null)
    {
        return array_slice(
            $this->client->getFilteredUsers(
                $filter,
                $this->filterType2FilterMethod('contains')
            ),
            $start,
            $limit);
    }

    /**
     * Define a group [implement only where required/possible]
     *
     * Set addGroup capability when implemented
     *
     * @param string $group
     *
     * @return  bool
     */
    //public function addGroup($group)
    //{
    // FIXME implement
    //    return false;
    //}

    /** @inheritDoc */
    public function retrieveGroups($start = 0, $limit = 0)
    {
        return array_slice($this->client->getCachedGroups(), $start, $limit);
    }

    /**
     * Return case sensitivity of the backend
     *
     * When your backend is caseinsensitive (eg. you can login with USER and
     * user) then you need to overwrite this method and return false
     *
     * @return bool
     */
    public function isCaseSensitive()
    {
        return true;
    }

    /**
     * Sanitize a given username
     *
     * This function is applied to any user name that is given to
     * the backend and should also be applied to any user name within
     * the backend before returning it somewhere.
     *
     * This should be used to enforce username restrictions.
     *
     * @param string $user username
     * @return string the cleaned username
     */
    public function cleanUser($user)
    {
        return $user;
    }

    /**
     * Sanitize a given groupname
     *
     * This function is applied to any groupname that is given to
     * the backend and should also be applied to any groupname within
     * the backend before returning it somewhere.
     *
     * This should be used to enforce groupname restrictions.
     *
     * Groupnames are to be passed without a leading '@' here.
     *
     * @param string $group groupname
     *
     * @return string the cleaned groupname
     */
    public function cleanGroup($group)
    {
        return $group;
    }

    /**
     * Check Session Cache validity [implement only where required/possible]
     *
     * DokuWiki caches user info in the user's session for the timespan defined
     * in $conf['auth_security_timeout'].
     *
     * This makes sure slow authentication backends do not slow down DokuWiki.
     * This also means that changes to the user database will not be reflected
     * on currently logged in users.
     *
     * To accommodate for this, the user manager plugin will touch a reference
     * file whenever a change is submitted. This function compares the filetime
     * of this reference file with the time stored in the session.
     *
     * This reference file mechanism does not reflect changes done directly in
     * the backend's database through other means than the user manager plugin.
     *
     * Fast backends might want to return always false, to force rechecks on
     * each page load. Others might want to use their own checking here. If
     * unsure, do not override.
     *
     * @param string $user - The username
     *
     * @return bool
     */
    public function useSessionCache($user)
    {
        return false;
    }

    /**
     * Convert DokuWiki filter type to method in the library
     *
     * @todo implement with proper constants once #3028 has been implemented
     * @param string $type
     * @return string
     */
    protected function filterType2FilterMethod($type)
    {
        $filtermethods = [
            'contains' => 'contains',
            'startswith' => 'startsWith',
            'endswith' => 'endsWith',
            'equals' => 'equals',
        ];

        if (isset($filtermethods[$type])) {
            return $filtermethods[$type];
        }

        return 'equals';
    }
}

