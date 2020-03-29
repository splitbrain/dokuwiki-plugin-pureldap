<?php

namespace dokuwiki\plugin\pureldap\classes;

use FreeDSx\Ldap\Entry\Entries;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\Filters;

class ADClient extends Client
{

    /** @inheritDoc */
    public function getUser($username, $fetchgroups = true)
    {
        if (!$this->autoAuth()) return null;

        $filter = Filters::and(
            Filters::equal('objectClass', 'user'),
            Filters::equal('userPrincipalName', $username)
        );
        $this->debug('Searching ' . $filter->toString(), __FILE__, __LINE__);

        try {
            /** @var Entries $entries */
            $entries = $this->ldap->search(Operations::search($filter));
        } catch (OperationException $e) {
            $this->fatal($e);
            return null;
        }
        if ($entries->count() !== 1) return null;
        $entry = $entries->first();
        return $this->entry2User($entry);
    }

    /** @inheritDoc */
    public function getGroups($match = null, $filtermethod = 'equal')
    {
        if (!$this->autoAuth()) return [];

        $filter = Filters::and(
            Filters::equal('objectClass', 'group')
        );
        if ($match !== null) {
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
                $groups[$entry->getDn()->toString()] = $this->attr2str($entry->get('cn'));
            }
        }

        return $groups;
    }

    /**
     * Fetch users matching the given filters
     *
     * @param array $match
     * @param string $filtermethod The method to use for filtering
     * @return array
     */
    public function getFilteredUsers($match, $filtermethod = 'equal')
    {
        if (!$this->autoAuth()) return [];

        $filter = Filters::and(Filters::equal('objectClass', 'user'));
        if (isset($match['user'])) {
            $filter->add(Filters::$filtermethod('userPrincipalName', $match['user']));
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
                $or->add(Filters::equal('memberOf', $dn));
            }
            $filter->add($or);
        }
        $this->debug('Searching ' . $filter->toString(), __FILE__, __LINE__);
        $search = Operations::search($filter);
        $paging = $this->ldap->paging($search);

        $users = [];
        while ($paging->hasEntries()) {
            try {
                $entries = $paging->getEntries();
            } catch (ProtocolException $e) {
                $this->fatal($e);
                return $users; // we return what we got so far
            }

            foreach ($entries as $entry) {
                $users[] = $this->entry2User($entry);
            }
        }

        return $users;
    }

    /**
     * Transform an LDAP entry to a user info array
     *
     * @param Entry $entry
     * @return array
     */
    protected function entry2User(Entry $entry)
    {
        return [
            'user' => $this->attr2str($entry->get('UserPrincipalName')),
            'name' => $this->attr2str($entry->get('DisplayName')) ?: $this->attr2str($entry->get('Name')),
            'mail' => $this->attr2str($entry->get('mail')),
            'dn' => $entry->getDn()->toString(),
            'grps' => $this->getUserGroups($entry), // we always return groups because its currently inexpensive
        ];
    }

    /**
     * Get the list of groups the given user is member of
     *
     * This method currently does no LDAP queries and thus is inexpensive.
     *
     * @param Entry $userentry
     * @return array
     * @todo implement nested group memberships
     */
    protected function getUserGroups(Entry $userentry)
    {
        $groups = [$this->config['defaultgroup']]; // always add default

        // we simply take the first CN= part of the group DN and return it as the group name
        // this should be correct for ActiveDirectory and saves us additional LDAP queries
        if ($userentry->has('memberOf')) {
            foreach ($userentry->get('memberOf')->getValues() as $dn) {
                list($cn) = explode(',', $dn, 2);
                $groups[] = substr($cn, 3);
            }
        }

        // resolving the primary group in AD is complicated but basically never needed
        // http://support.microsoft.com/?kbid=321360
        $gid = $userentry->get('primaryGroupID')->firstValue();
        if ($gid == 513) {
            $groups[] = 'Domain Users';
        }

        return $groups;
    }
}
