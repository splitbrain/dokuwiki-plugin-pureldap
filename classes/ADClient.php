<?php

namespace dokuwiki\plugin\pureldap\classes;

use dokuwiki\Utf8\PhpString;
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Entries;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\Filters;

/**
 * Implement Active Directory Specifics
 */
class ADClient extends Client
{
    public const ADS_UF_DONT_EXPIRE_PASSWD = 0x10000;

    /**
     * @var GroupHierarchyCache
     * @see getGroupHierarchyCache
     */
    protected $gch;

    /** @inheritDoc */
    public function getUser($username, $fetchgroups = true)
    {
        $entry = $this->getUserEntry($username);
        if ($entry === null) return null;
        return $this->entry2User($entry);
    }

    /**
     * Get the LDAP entry for the given user
     *
     * @param string $username
     * @return Entry|null
     */
    protected function getUserEntry($username)
    {
        if (!$this->autoAuth()) return null;
        $samaccountname = $this->simpleUser($username);
        $userprincipal = $this->qualifiedUser($username);

        $filter = Filters::and(
            Filters::equal('objectClass', 'user'),
            Filters::or(
                Filters::equal('sAMAccountName', $samaccountname),
                Filters::equal('userPrincipalName', $userprincipal)
            )

        );
        $this->debug('Searching ' . $filter->toString(), __FILE__, __LINE__);

        try {
            $attributes = $this->userAttributes();
            $entries = $this->ldap->search(Operations::search($filter, ...$attributes));
        } catch (OperationException $e) {
            $this->fatal($e);
            return null;
        }
        if ($entries->count() !== 1) return null;
        return $entries->first();
    }

    /** @inheritDoc */
    public function setPassword($username, $newpass, $oldpass = null)
    {
        if (!$this->autoAuth()) return false;

        $entry = $this->getUserEntry($username);
        if ($entry === null) {
            $this->error("User '$username' not found", __FILE__, __LINE__);
            return false;
        }

        if ($oldpass) {
            // if an old password is given, this is a self-service password change
            // this has to be executed as the user themselves, not as the admin
            if ($this->isAuthenticated !== $this->prepareBindUser($username)) {
                if (!$this->authenticate($username, $oldpass)) {
                    $this->error("Old password for '$username' is wrong", __FILE__, __LINE__);
                    return false;
                }
            }

            $entry->remove('unicodePwd', $this->encodePassword($oldpass));
            $entry->add('unicodePwd', $this->encodePassword($newpass));
        } else {
            // run as admin user
            $entry->set('unicodePwd', $this->encodePassword($newpass));
        }

        try {
            $this->ldap->update($entry);
        } catch (OperationException $e) {
            $this->fatal($e);
            return false;
        }
        return true;
    }

    /** @inheritDoc */
    public function getGroups($match = null, $filtermethod = self::FILTER_EQUAL)
    {
        if (!$this->autoAuth()) return [];

        $filter = Filters::and(
            Filters::equal('objectClass', 'group')
        );
        if ($match !== null) {
            // FIXME this is a workaround that removes regex anchors and quoting as passed by the groupuser plugin
            // a proper fix requires splitbrain/dokuwiki#3028 to be implemented
            $match = ltrim($match, '^');
            $match = rtrim($match, '$');
            $match = stripslashes($match);

            $filter->add(Filters::$filtermethod('cn', $match));
        }

        $this->debug('Searching ' . $filter->toString(), __FILE__, __LINE__);
        $search = Operations::search($filter, 'cn');
        $paging = $this->ldap->paging($search);

        $groups = [];
        while ($paging->hasEntries()) {
            try {
                $entries = $paging->getEntries();
            } catch (OperationException $e) {
                $this->fatal($e);
                return $groups; // we return what we got so far
            }

            foreach ($entries as $entry) {
                /** @var Entry $entry */
                $groups[$entry->getDn()->toString()] = $this->cleanGroup($this->attr2str($entry->get('cn')));
            }
        }

        asort($groups);
        return $groups;
    }

    /**
     * Fetch users matching the given filters
     *
     * @param array $match
     * @param string $filtermethod The method to use for filtering
     * @return array
     */
    public function getFilteredUsers($match, $filtermethod = self::FILTER_EQUAL)
    {
        if (!$this->autoAuth()) return [];

        $filter = Filters::and(Filters::equal('objectClass', 'user'));
        if (isset($match['user'])) {
            $filter->add(Filters::$filtermethod('sAMAccountName', $this->simpleUser($match['user'])));
        }
        if (isset($match['name'])) {
            $filter->add(Filters::$filtermethod('displayName', $match['name']));
        }
        if (isset($match['mail'])) {
            $filter->add(Filters::$filtermethod('mail', $match['mail']));
        }
        if (isset($match['grps'])) {
            // memberOf can not be checked with a substring match, so we need to get the right groups first
            $groups = $this->getGroups($match['grps'], $filtermethod);
            $groupDNs = array_keys($groups);

            if ($this->config['recursivegroups']) {
                $gch = $this->getGroupHierarchyCache();
                foreach ($groupDNs as $dn) {
                    $groupDNs = array_merge($groupDNs, $gch->getChildren($dn));
                }
                $groupDNs = array_unique($groupDNs);
            }

            $or = Filters::or();
            foreach ($groupDNs as $dn) {
                // domain users membership is in primary group
                if ($this->dn2group($dn) === $this->config['primarygroup']) {
                    $or->add(Filters::equal('primaryGroupID', 513));
                    continue;
                }
                // find members of this exact group
                $or->add(Filters::equal('memberOf', $dn));
            }
            $filter->add($or);
        }

        $this->debug('Searching ' . $filter->toString(), __FILE__, __LINE__);
        $attributes = $this->userAttributes();
        $search = Operations::search($filter, ...$attributes);
        $paging = $this->ldap->paging($search);

        $users = [];
        while ($paging->hasEntries()) {
            try {
                $entries = $paging->getEntries();
            } catch (OperationException $e) {
                $this->fatal($e);
                break; // we abort and return what we have so far
            }

            foreach ($entries as $entry) {
                $userinfo = $this->entry2User($entry);
                $users[$userinfo['user']] = $userinfo;
            }
        }

        ksort($users);
        return $users;
    }

    /** @inheritDoc */
    public function cleanUser($user)
    {
        return $this->simpleUser($user);
    }

    /** @inheritDoc */
    public function cleanGroup($group)
    {
        return PhpString::strtolower($group);
    }

    /** @inheritDoc */
    protected function prepareBindUser($user)
    {
        // add account suffix
        return $this->qualifiedUser($user);
    }

    /**
     * Initializes the Group Cache for nested groups
     *
     * @return GroupHierarchyCache
     */
    public function getGroupHierarchyCache()
    {
        if ($this->gch === null) {
            if (!$this->autoAuth()) return null;
            $this->gch = new GroupHierarchyCache($this->ldap, $this->config['usefscache']);
        }
        return $this->gch;
    }

    /**
     * userPrincipalName in the form <user>@<suffix>
     *
     * @param string $user
     * @return string
     */
    protected function qualifiedUser($user)
    {
        $user = $this->simpleUser($user); // strip any existing qualifiers
        if (!$this->config['suffix']) {
            $this->error('No account suffix set. Logins may fail.', __FILE__, __LINE__);
        }

        return $user . '@' . $this->config['suffix'];
    }

    /**
     * Removes the account suffix from the given user. Should match the SAMAccountName
     *
     * @param string $user
     * @return string
     */
    protected function simpleUser($user)
    {
        $user = PhpString::strtolower($user);
        $user = preg_replace('/@.*$/', '', $user);
        $user = preg_replace('/^.*\\\\/', '', $user);
        return $user;
    }

    /**
     * Transform an LDAP entry to a user info array
     *
     * @param Entry $entry
     * @return array
     */
    protected function entry2User(Entry $entry)
    {
        // prefer userPrincipalName over sAMAccountName
        $user = $this->simpleUser($this->attr2str($entry->get('userPrincipalName')));
        if($user === '') $user = $this->simpleUser($this->attr2str($entry->get('sAMAccountName')));

        $user = [
            'user' => $user,
            'name' => $this->attr2str($entry->get('DisplayName')) ?: $this->attr2str($entry->get('Name')),
            'mail' => $this->attr2str($entry->get('mail')),
            'dn' => $entry->getDn()->toString(),
            'grps' => $this->getUserGroups($entry), // we always return groups because its currently inexpensive
        ];

        // handle password expiry info
        $lastChange = $this->attr2str($entry->get('pwdlastset'));
        if ($lastChange) {
            $lastChange = (int)substr($lastChange, 0, -7); // remove last 7 digits (100ns intervals to seconds)
            $lastChange -= 11_644_473_600; // convert from 1601 to 1970 epoch
        }
        $user['lastpwd'] = (int)$lastChange;
        $user['expires'] = !($this->attr2str($entry->get('useraccountcontrol')) & self::ADS_UF_DONT_EXPIRE_PASSWD);

        // get additional attributes
        foreach ($this->config['attributes'] as $attr) {
            $user[$attr] = $this->attr2str($entry->get($attr));
        }

        return $user;
    }

    /**
     * Get the list of groups the given user is member of
     *
     * This method currently does no LDAP queries and thus is inexpensive.
     *
     * @param Entry $userentry
     * @return array
     */
    protected function getUserGroups(Entry $userentry)
    {
        $groups = [];

        if ($userentry->has('memberOf')) {
            $groupDNs = $userentry->get('memberOf')->getValues();

            if ($this->config['recursivegroups']) {
                $gch = $this->getGroupHierarchyCache();
                foreach ($groupDNs as $dn) {
                    $groupDNs = array_merge($groupDNs, $gch->getParents($dn));
                }

                $groupDNs = array_unique($groupDNs);
            }
            $groups = array_map([$this, 'dn2group'], $groupDNs);
        }

        $groups[] = $this->config['defaultgroup']; // always add default

        // resolving the primary group in AD is complicated but basically never needed
        // http://support.microsoft.com/?kbid=321360
        $gid = $userentry->get('primaryGroupID')->firstValue();
        if ($gid == 513) {
            $groups[] = $this->cleanGroup($this->config['primarygroup']);
        }

        sort($groups);
        return $groups;
    }

    /** @inheritDoc */
    protected function userAttributes()
    {
        $attr = parent::userAttributes();
        $attr[] = new Attribute('sAMAccountName');
        $attr[] = new Attribute('userPrincipalName');
        $attr[] = new Attribute('Name');
        $attr[] = new Attribute('primaryGroupID');
        $attr[] = new Attribute('memberOf');
        $attr[] = new Attribute('pwdlastset');
        $attr[] = new Attribute('useraccountcontrol');

        return $attr;
    }

    /**
     * Queries the maximum password age from the AD server
     *
     * Note: we do not check if passwords actually are set to expire here. This is encoded in the lower 32bit
     * of the returned 64bit integer (see link below). We do not check this because it would require us to
     * actually do large integer math and we can simply assume it's enabled when the age check was requested in
     * DokuWiki configuration.
     *
     * @link http://msdn.microsoft.com/en-us/library/ms974598.aspx
     * @param bool $useCache should a filesystem cache be used if available?
     * @return int The maximum password age in seconds
     */
    public function getMaxPasswordAge($useCache = true)
    {
        global $conf;
        $cachename = getCacheName('maxPwdAge', '.pureldap-maxPwdAge');
        $cachetime = @filemtime($cachename);

        // valid file system cache? use it
        if ($useCache && $cachetime && (time() - $cachetime) < $conf['auth_security_timeout']) {
            return (int)file_get_contents($cachename);
        }

        if (!$this->autoAuth()) return 0;

        $attr = new Attribute('maxPwdAge');
        try {
            $entry = $this->ldap->read(
                $this->getConf('base_dn'),
                [$attr]
            );
        } catch (OperationException $e) {
            $this->fatal($e);
            return 0;
        }
        if (!$entry) return 0;
        $maxPwdAge = $entry->get($attr)->firstValue();

        // MS returns 100 nanosecond intervals, we want seconds
        // we operate on strings to avoid integer overflow
        // we also want a positive value, so we trim off the leading minus sign
        // only then we convert to int
        $maxPwdAge = (int)ltrim(substr($maxPwdAge, 0, -7), '-');

        file_put_contents($cachename, $maxPwdAge);
        return $maxPwdAge;
    }

    /**
     * Extract the group name from the DN
     *
     * @param string $dn
     * @return string
     */
    protected function dn2group($dn)
    {
        [$cn] = explode(',', $dn, 2);
        return $this->cleanGroup(substr($cn, 3));
    }

    /**
     * Encode a password for transmission over LDAP
     *
     * Passwords are encoded as UTF-16LE strings encapsulated in quotes.
     *
     * @param string $password The password to encode
     * @return string
     */
    protected function encodePassword($password)
    {
        $password = "\"" . $password . "\"";

        if (function_exists('iconv')) {
            $adpassword = iconv('UTF-8', 'UTF-16LE', $password);
        } elseif (function_exists('mb_convert_encoding')) {
            $adpassword = mb_convert_encoding($password, "UTF-16LE", "UTF-8");
        } else {
            // this will only work for ASCII7 passwords
            $adpassword = '';
            for ($i = 0; $i < strlen($password); $i++) {
                $adpassword .= "$password[$i]\000";
            }
        }
        return $adpassword;
    }
}
