<?php

namespace dokuwiki\plugin\pureldap\classes;

use dokuwiki\PassHash;
use dokuwiki\Utf8\PhpString;
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Search\Filters;

/**
 * Universal LDAP client.
 *
 * Implements the generic side of every {@see Client} contract using
 * configurable filter and attribute names. Active Directory and other
 * directory flavours specialise this class by seeding their own defaults
 * (see {@see ADClient}) and, where needed, overriding a small set of hook
 * methods for protocol details that cannot be reduced to configuration.
 *
 * Hooks intended for subclass override:
 *  - extractLastpwd(Entry): int
 *  - extractExpires(Entry): bool
 *  - additionalGroups(Entry): string[]
 *  - groupMembershipFilter(string $dn): FilterInterface
 */
class LDAPClient extends Client
{
    /** @var GroupHierarchyCache|null */
    protected $gch;

    /** @inheritDoc */
    protected function prepareConfig($config)
    {
        $config = parent::prepareConfig($config);

        $ldapDefaults = [
            'userkey' => 'uid',
            'groupkey' => 'cn',
            'namekey' => 'cn',
            'mailkey' => 'mail',
            'userClass' => 'inetOrgPerson',
            'groupClass' => 'groupOfNames',
            'memberof_attr' => 'memberOf',
            'password_attr' => 'userPassword',
            'modPass' => 1,
            'modPassPlain' => 0,
        ];
        foreach ($ldapDefaults as $key => $val) {
            if (!isset($config[$key]) || $config[$key] === '' || $config[$key] === []) {
                $config[$key] = $val;
            }
        }
        return $config;
    }

    /** @inheritDoc */
    public function getUser($username, $fetchgroups = true)
    {
        $entry = $this->getUserEntry($username);
        if ($entry === null) return null;
        return $this->entry2User($entry);
    }

    /** @inheritDoc */
    public function getUserEntry($username)
    {
        if (!$this->autoAuth()) return null;
        $username = $this->cleanUser($username);

        $filter = Filters::and(
            Filters::equal('objectClass', $this->config['userClass']),
            Filters::equal($this->config['userkey'], $username)
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
    public function getGroups($match = null, $filtermethod = self::FILTER_EQUAL)
    {
        if (!$this->autoAuth()) return [];

        $filter = Filters::and(Filters::equal('objectClass', $this->config['groupClass']));
        if ($match !== null) {
            // FIXME this is a workaround that removes regex anchors and quoting as passed by the groupuser plugin
            // a proper fix requires splitbrain/dokuwiki#3028 to be implemented
            $match = ltrim($match, '^');
            $match = rtrim($match, '$');
            $match = stripslashes($match);

            $filter->add(Filters::$filtermethod($this->config['groupkey'], $match));
        }

        $this->debug('Searching ' . $filter->toString(), __FILE__, __LINE__);
        $search = Operations::search($filter, $this->config['groupkey']);
        $paging = $this->ldap->paging($search);

        $groups = [];
        while ($paging->hasEntries()) {
            try {
                $entries = $paging->getEntries();
            } catch (OperationException $e) {
                $this->fatal($e);
                return $groups;
            }

            foreach ($entries as $entry) {
                /** @var Entry $entry */
                $groups[$entry->getDn()->toString()] = $this->cleanGroup(
                    $this->attr2str($entry->get($this->config['groupkey']))
                );
            }
        }

        asort($groups);
        return $groups;
    }

    /**
     * Fetch users matching the given filters
     *
     * @param array $match
     * @param string $filtermethod
     * @return array
     */
    public function getFilteredUsers($match, $filtermethod = self::FILTER_EQUAL)
    {
        if (!$this->autoAuth()) return [];

        $filter = Filters::and(Filters::equal('objectClass', $this->config['userClass']));

        if (isset($match['user'])) {
            $filter->add($this->orOverKeys('userkey', $match['user'], $filtermethod, true));
        }
        if (isset($match['name'])) {
            $filter->add($this->orOverKeys('namekey', $match['name'], $filtermethod, false));
        }
        if (isset($match['mail'])) {
            $filter->add(Filters::$filtermethod($this->config['mailkey'], $match['mail']));
        }
        if (isset($match['grps'])) {
            // memberOf can't be substring-matched; resolve to group DNs first
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
                $or->add($this->groupMembershipFilter($dn));
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
                break;
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
        return PhpString::strtolower($user);
    }

    /** @inheritDoc */
    public function cleanGroup($group)
    {
        return PhpString::strtolower($group);
    }

    /**
     * Initialise the group hierarchy cache used for recursive memberOf
     * lookups.
     *
     * @return GroupHierarchyCache|null
     */
    public function getGroupHierarchyCache()
    {
        if ($this->gch === null) {
            if (!$this->autoAuth()) return null;
            $this->gch = new GroupHierarchyCache(
                $this->ldap,
                $this->config['usefscache'],
                $this->groupHierarchyFilter(),
                $this->config['memberof_attr'],
                $this->config['groupkey']
            );
        }
        return $this->gch;
    }

    /**
     * Filter used when enumerating all groups for hierarchy caching.
     *
     * @return FilterInterface
     */
    protected function groupHierarchyFilter()
    {
        return Filters::equal('objectClass', $this->config['groupClass']);
    }

    /** @inheritDoc */
    protected function passwordAttribute()
    {
        return $this->config['password_attr'];
    }

    /** @inheritDoc */
    protected function encodePassword($password)
    {
        if ($this->config['modPassPlain']) {
            return $password;
        }
        $phash = new PassHash();
        return $phash->hash_ssha($password);
    }

    /** @inheritDoc */
    public function canModPass()
    {
        return (bool)$this->config['modPass'];
    }

    /** @inheritDoc */
    protected function userAttributes()
    {
        $attr = [new Attribute('dn')];
        foreach ($this->splitConfigList('userkey') as $key) $attr[] = new Attribute($key);
        foreach ($this->splitConfigList('namekey') as $key) $attr[] = new Attribute($key);
        $attr[] = new Attribute($this->config['mailkey']);
        $attr[] = new Attribute($this->config['memberof_attr']);
        foreach ($this->config['attributes'] as $attribute) {
            $attr[] = new Attribute($attribute);
        }
        return $attr;
    }

    /**
     * Build the user info array from an LDAP entry.
     *
     * @param Entry $entry
     * @return array
     */
    protected function entry2User(Entry $entry)
    {
        $info = [
            'user' => $this->cleanUser($this->firstNonEmptyAttr($entry, $this->splitConfigList('userkey'))),
            'name' => $this->firstNonEmptyAttr($entry, $this->splitConfigList('namekey')),
            'mail' => $this->attr2str($entry->get($this->config['mailkey'])),
            'dn' => $entry->getDn()->toString(),
            'grps' => $this->getUserGroups($entry),
        ];

        $info['lastpwd'] = $this->extractLastpwd($entry);
        $info['expires'] = $this->extractExpires($entry);

        foreach ($this->config['attributes'] as $attr) {
            $info[$attr] = $this->attr2str($entry->get($attr));
        }

        return $info;
    }

    /**
     * Compute the user's group memberships from the configured memberOf
     * attribute on the user entry. Subclasses may add directory-specific
     * groups via {@see additionalGroups()}.
     *
     * @param Entry $userentry
     * @return string[]
     */
    protected function getUserGroups(Entry $userentry)
    {
        $groups = [];
        $memberAttr = $this->config['memberof_attr'];

        if ($userentry->has($memberAttr)) {
            $groupDNs = $userentry->get($memberAttr)->getValues();
            if ($this->config['recursivegroups']) {
                $gch = $this->getGroupHierarchyCache();
                foreach ($groupDNs as $dn) {
                    $groupDNs = array_merge($groupDNs, $gch->getParents($dn));
                }
                $groupDNs = array_unique($groupDNs);
            }
            $groups = array_map([$this, 'dn2group'], $groupDNs);
        }

        $groups[] = $this->config['defaultgroup'];
        $groups = array_merge($groups, $this->additionalGroups($userentry));

        sort($groups);
        return $groups;
    }

    /**
     * Hook: timestamp of the user's last password change. Default 0
     * indicates the information is not available.
     *
     * @param Entry $entry
     * @return int Unix timestamp
     */
    protected function extractLastpwd(Entry $entry)
    {
        return 0;
    }

    /**
     * Hook: whether the user's password is subject to expiry policy.
     *
     * @param Entry $entry
     * @return bool
     */
    protected function extractExpires(Entry $entry)
    {
        return false;
    }

    /**
     * Hook: directory-specific extra groups computed from data on the user
     * entry. Default returns an empty list.
     *
     * @param Entry $userentry
     * @return string[]
     */
    protected function additionalGroups(Entry $userentry)
    {
        return [];
    }

    /**
     * Hook: build the filter clause that selects members of the given
     * group DN. Default uses the standard memberOf reference.
     *
     * @param string $groupDn
     * @return FilterInterface
     */
    protected function groupMembershipFilter($groupDn)
    {
        return Filters::equal($this->config['memberof_attr'], $groupDn);
    }

    /**
     * Extract a group's short name from its DN by stripping the leading
     * attribute name (CN= / uid= / etc.) from the first RDN.
     *
     * @param string $dn
     * @return string
     */
    protected function dn2group($dn)
    {
        [$rdn] = explode(',', $dn, 2);
        $eq = strpos($rdn, '=');
        if ($eq === false) return $this->cleanGroup($rdn);
        return $this->cleanGroup(substr($rdn, $eq + 1));
    }

    /**
     * Split a config value into an array of attribute names. Accepts
     * arrays or comma-separated strings; trims whitespace and drops empty
     * entries.
     *
     * @param string $key
     * @return string[]
     */
    protected function splitConfigList($key)
    {
        $val = $this->config[$key] ?? '';
        if (is_array($val)) $val = implode(',', $val);
        $parts = array_filter(array_map('trim', explode(',', (string)$val)), 'strlen');
        return array_values($parts);
    }

    /**
     * Return the first non-empty attribute value from the given list of
     * candidate attribute names.
     *
     * @param Entry $entry
     * @param string[] $keys
     * @return string
     */
    protected function firstNonEmptyAttr(Entry $entry, array $keys)
    {
        foreach ($keys as $key) {
            $val = $this->attr2str($entry->get($key));
            if ($val !== '') return $val;
        }
        return '';
    }

    /**
     * Build a filter clause that matches $value against any of the
     * attributes named in the comma-separated config value at $configKey.
     *
     * @param string $configKey config key holding the attribute list
     * @param string $value value to match against
     * @param string $filtermethod equal|contains|startsWith|endsWith
     * @param bool $cleanUser whether to run the value through cleanUser()
     *                       (used for user-name matching to apply
     *                        cleanUser normalisation, e.g. AD's UPN strip)
     * @return FilterInterface
     */
    protected function orOverKeys($configKey, $value, $filtermethod, $cleanUser)
    {
        if ($cleanUser) $value = $this->cleanUser($value);
        $keys = $this->splitConfigList($configKey);
        if (count($keys) === 1) {
            return Filters::$filtermethod($keys[0], $value);
        }
        $or = Filters::or();
        foreach ($keys as $key) {
            $or->add(Filters::$filtermethod($key, $value));
        }
        return $or;
    }
}
