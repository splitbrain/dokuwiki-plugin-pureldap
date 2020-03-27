<?php

namespace dokuwiki\plugin\pureldap\classes;

use FreeDSx\Ldap\Entry\Entries;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
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

        try {
            /** @var Entries $entries */
            $entries = $this->ldap->search(Operations::search($filter));
        } catch (OperationException $e) {
            $this->debug($e);
            return null;
        }
        if ($entries->count() !== 1) return null;
        $entry = $entries->first();

        return [
            'user' => $username,
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
            foreach ($userentry->get('memberOf')->getValues() as $line) {
                list($cn) = explode(',', $line, 2);
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
