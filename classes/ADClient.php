<?php

namespace dokuwiki\plugin\pureldap\classes;

use dokuwiki\Utf8\PhpString;
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Entries;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\Filters;

/**
 * Implement Active Directory Specifics
 */
class ADClient extends Client
{
    // see https://docs.microsoft.com/en-us/windows/win32/adsi/search-filter-syntax
    const LDAP_MATCHING_RULE_IN_CHAIN = '1.2.840.113556.1.4.1941';

    /** @inheritDoc */
    public function getUser($username, $fetchgroups = true)
    {
        if (!$this->autoAuth()) return null;
        $username = $this->simpleUser($username);

        $filter = Filters::and(
            Filters::equal('objectClass', 'user'),
            Filters::equal('sAMAccountName', $this->simpleUser($username))
        );
        $this->debug('Searching ' . $filter->toString(), __FILE__, __LINE__);

        try {
            /** @var Entries $entries */
            $attributes = $this->userAttributes();
            $entries = $this->ldap->search(Operations::search($filter, ...$attributes));
        } catch (OperationException $e) {
            $this->fatal($e);
            return null;
        }
        if ($entries->count() !== 1) return null;
        $entry = $entries->first();
        return $this->entry2User($entry);
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
            } catch (ProtocolException $e) {
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
            $or = Filters::or();
            foreach ($groups as $dn => $group) {
                // domain users membership is in primary group
                if ($group === $this->config['primarygroup']) {
                    $or->add(Filters::equal('primaryGroupID', 513));
                    continue;
                }

                $or->add(Filters::equal('memberOf', $dn)); // FIXME handle recursive groups
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
            } catch (ProtocolException $e) {
                $this->fatal($e);
                break; // we abort and return what we have so far
            }

            foreach ($entries as $entry) {
                $userinfo = $this->entry2User($entry);
                $users[$userinfo['user']] = $this->entry2User($entry);
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
    public function prepareBindUser($user)
    {
        $user = $this->qualifiedUser($user); // add account suffix
        return $user;
    }

    /**
     * @inheritDoc
     * userPrincipalName in the form <user>@<suffix>
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
     * @inheritDoc
     * Removes the account suffix from the given user. Should match the SAMAccountName
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
        $user = [
            'user' => $this->simpleUser($this->attr2str($entry->get('sAMAccountName'))),
            'name' => $this->attr2str($entry->get('DisplayName')) ?: $this->attr2str($entry->get('Name')),
            'mail' => $this->attr2str($entry->get('mail')),
            'dn' => $entry->getDn()->toString(),
            'grps' => $this->getUserGroups($entry), // we always return groups because its currently inexpensive
        ];

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
        $groups = [$this->config['defaultgroup']]; // always add default

        // resolving the primary group in AD is complicated but basically never needed
        // http://support.microsoft.com/?kbid=321360
        $gid = $userentry->get('primaryGroupID')->firstValue();
        if ($gid == 513) {
            $groups[] = $this->cleanGroup('domain users');
        }

        if ($this->config['recursivegroups']) {
            // we do an additional query for the user's groups asking the AD server to resolve nested
            // groups for us
            if (!$this->autoAuth()) return $groups;
            $filter = Filters::extensible('member', (string)$userentry->getDn(), self::LDAP_MATCHING_RULE_IN_CHAIN,
                true);
            $search = Operations::search($filter, 'name');
            $paging = $this->ldap->paging($search);
            while ($paging->hasEntries()) {
                try {
                    $entries = $paging->getEntries();
                } catch (ProtocolException $e) {
                    return $groups; // return what we have
                }
                /** @var Entry $entry */
                foreach ($entries as $entry) {
                    $groups[] = $this->cleanGroup(($entry->get('name')->getValues())[0]);
                }
            }

        } elseif ($userentry->has('memberOf')) {
            // we simply take the first CN= part of the group DN and return it as the group name
            // this should be correct for ActiveDirectory and saves us additional LDAP queries
            foreach ($userentry->get('memberOf')->getValues() as $dn) {
                list($cn) = explode(',', $dn, 2);
                $groups[] = $this->cleanGroup(substr($cn, 3));
            }
        }

        sort($groups);
        return $groups;
    }

    /** @inheritDoc */
    protected function userAttributes()
    {
        $attr = parent::userAttributes();
        $attr[] = new Attribute('sAMAccountName');
        $attr[] = new Attribute('Name');
        $attr[] = new Attribute('primaryGroupID');
        $attr[] = new Attribute('memberOf');

        return $attr;
    }
}
