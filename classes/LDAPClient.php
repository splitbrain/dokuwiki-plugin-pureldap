<?php

namespace dokuwiki\plugin\pureldap\classes;

use dokuwiki\PassHash;
use dokuwiki\Utf8\PhpString;
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\BindException;
use FreeDSx\Ldap\Exception\FilterParseException;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Search\FilterParser;
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
            'group_member_attr' => 'memberUid',
            'password_attr' => 'userPassword',
            'userfilter' => '',
            'groupfilter' => '',
            'usertree' => '',
            'grouptree' => '',
            'userscope' => 'sub',
            'groupscope' => 'sub',
            'binddn' => '',
            'group_strategy' => 'auto',
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

    /**
     * Authenticate a user.
     *
     * When the subclass can produce a bindable identifier from the input
     * (AD's UPN, or a configured binddn template) we bind directly.
     * Otherwise we go through the standard search-then-bind dance:
     * authenticate as the admin, locate the user entry, then bind as
     * their full DN.
     *
     * @inheritDoc
     */
    public function authenticate($user, $pass)
    {
        if ($this->usesDirectBind()) {
            return parent::authenticate($user, $pass);
        }

        if (!$this->autoAuth()) {
            throw new BindException('Cannot resolve user: directory bind failed', 49);
        }
        $entry = $this->getUserEntry($user);
        if ($entry === null) {
            throw new BindException('User not found: ' . $user, 49);
        }
        return $this->bindAs($entry->getDn()->toString(), $pass);
    }

    /**
     * Whether the subclass can transform the input username into a
     * directly-bindable identifier without an LDAP lookup. Drives the
     * authenticate() flow.
     *
     * @return bool
     */
    protected function usesDirectBind()
    {
        return $this->config['binddn'] !== '';
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

        $filter = $this->buildUserSearchFilter($username);
        if ($filter === null) return null;

        $this->debug('Searching ' . $filter->toString(), __FILE__, __LINE__);

        try {
            $request = $this->applySearchScope(
                Operations::search($filter, ...$this->userAttributes()),
                $this->config['usertree'],
                $this->config['userscope']
            );
            $entries = $this->ldap->search($request);
        } catch (OperationException $e) {
            $this->fatal($e);
            return null;
        }
        if ($entries->count() !== 1) return null;
        return $entries->first();
    }

    /**
     * Build the user-search filter, honouring a configured userfilter
     * template if present and otherwise falling back to a structural
     * match on userkey + userClass.
     *
     * @param string $username
     * @return FilterInterface|null
     */
    protected function buildUserSearchFilter($username)
    {
        $template = $this->config['userfilter'] ?? '';
        if ($template !== '') {
            $placeholders = $this->userSearchPlaceholders($username);
            $filterStr = $this->substitute($template, $placeholders);
            try {
                return FilterParser::parse($filterStr);
            } catch (FilterParseException $e) {
                $this->error('Could not parse userfilter: ' . $filterStr, __FILE__, __LINE__);
                return null;
            }
        }

        return Filters::and(
            Filters::equal('objectClass', $this->config['userClass']),
            $this->orOverKeys('userkey', $username, self::FILTER_EQUAL, true)
        );
    }

    /**
     * Hook: placeholders available to the userfilter template. Subclasses
     * may add directory-specific names (e.g. AD's `qualifieduser`).
     *
     * @param string $username
     * @return array
     */
    protected function userSearchPlaceholders($username)
    {
        return [
            'user' => $this->cleanUser($username),
        ];
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
        $search = $this->applySearchScope(
            Operations::search($filter, $this->config['groupkey']),
            $this->config['grouptree'],
            $this->config['groupscope']
        );
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
            $clause = $this->buildGroupMembershipClause($match['grps'], $filtermethod);
            if ($clause === null) {
                // No matching group, so no users can match either.
                return [];
            }
            $filter->add($clause);
        }

        $this->debug('Searching ' . $filter->toString(), __FILE__, __LINE__);
        $search = $this->applySearchScope(
            Operations::search($filter, ...$this->userAttributes()),
            $this->config['usertree'],
            $this->config['userscope']
        );
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

    /**
     * Apply the configured search base and scope to a SearchRequest.
     *
     * @param SearchRequest $request
     * @param string $base Empty falls back to the bind context
     * @param string $scope sub|one|base
     * @return SearchRequest
     */
    protected function applySearchScope(SearchRequest $request, $base, $scope)
    {
        if ($base !== '') {
            $request->setBaseDn($base);
        }
        switch ($scope) {
            case 'base':
                $request->setScope(SearchRequest::SCOPE_BASE_OBJECT);
                break;
            case 'one':
                $request->setScope(SearchRequest::SCOPE_SINGLE_LEVEL);
                break;
            case 'sub':
            default:
                $request->setScope(SearchRequest::SCOPE_WHOLE_SUBTREE);
                break;
        }
        return $request;
    }

    /**
     * When a binddn template is configured, substitute %{user} (and any
     * other placeholders from userSearchPlaceholders) so the user binds
     * directly with that DN instead of being looked up first.
     *
     * @inheritDoc
     */
    protected function prepareBindUser($user)
    {
        $template = $this->config['binddn'];
        if ($template === '') return $user;
        return $this->substitute($template, $this->userSearchPlaceholders($user));
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
        if ($this->config['groupfilter'] !== '') {
            // grouptree resolution may reference the user's gid in its filter
            $attr[] = new Attribute('gidNumber');
        }
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
     * Compute the user's group memberships using the configured group
     * strategy. Subclasses may add directory-specific groups via
     * {@see additionalGroups()}.
     *
     * @param Entry $userentry
     * @return string[]
     */
    protected function getUserGroups(Entry $userentry)
    {
        switch ($this->resolveGroupStrategy($userentry)) {
            case 'grouptree':
                $groups = $this->groupsFromGroupTree($userentry);
                break;
            case 'memberof':
                $groups = $this->groupsFromMemberOf($userentry);
                break;
            case 'none':
            default:
                $groups = [];
                break;
        }

        $groups[] = $this->config['defaultgroup'];
        $groups = array_merge($groups, $this->additionalGroups($userentry));

        sort($groups);
        return $groups;
    }

    /**
     * Resolve `group_strategy=auto` to a concrete strategy based on what
     * the directory offers; pass other values through unchanged.
     *
     * @param Entry $userentry
     * @return string one of grouptree|memberof|none
     */
    protected function resolveGroupStrategy(Entry $userentry)
    {
        $strategy = $this->config['group_strategy'] ?? 'auto';
        if ($strategy !== 'auto') return $strategy;

        if ($this->config['groupfilter'] !== '') return 'grouptree';
        if ($userentry->has($this->config['memberof_attr'])) return 'memberof';
        return 'none';
    }

    /**
     * Resolve groups by walking the memberOf attribute on the user entry,
     * with optional recursive expansion through the hierarchy cache.
     *
     * @param Entry $userentry
     * @return string[]
     */
    protected function groupsFromMemberOf(Entry $userentry)
    {
        $memberAttr = $this->config['memberof_attr'];
        if (!$userentry->has($memberAttr)) return [];

        $groupDNs = $userentry->get($memberAttr)->getValues();
        if ($this->config['recursivegroups']) {
            $gch = $this->getGroupHierarchyCache();
            foreach ($groupDNs as $dn) {
                $groupDNs = array_merge($groupDNs, $gch->getParents($dn));
            }
            $groupDNs = array_unique($groupDNs);
        }
        return array_map([$this, 'dn2group'], $groupDNs);
    }

    /**
     * Resolve groups by running a configured groupfilter against the
     * grouptree (the RFC 2307 / posixGroup pattern). Placeholders
     * `%{user}`, `%{dn}`, `%{gid}` are available in the template.
     *
     * @param Entry $userentry
     * @return string[]
     */
    protected function groupsFromGroupTree(Entry $userentry)
    {
        if (!$this->autoAuth()) return [];

        $template = $this->config['groupfilter'];
        $username = $this->firstNonEmptyAttr($userentry, $this->splitConfigList('userkey'));
        $placeholders = $this->userSearchPlaceholders($username);
        $placeholders['dn'] = $userentry->getDn()->toString();
        $placeholders['gid'] = $this->attr2str($userentry->get('gidNumber'));

        $filterStr = $this->substitute($template, $placeholders);
        try {
            $filter = FilterParser::parse($filterStr);
        } catch (FilterParseException $e) {
            $this->error('Could not parse groupfilter: ' . $filterStr, __FILE__, __LINE__);
            return [];
        }

        $search = $this->applySearchScope(
            Operations::search($filter, $this->config['groupkey']),
            $this->config['grouptree'],
            $this->config['groupscope']
        );
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
                $groups[] = $this->cleanGroup($this->attr2str($entry->get($this->config['groupkey'])));
            }
        }
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
     * Build the filter clause for `getFilteredUsers(['grps' => ...])`.
     *
     * In memberof-style directories the user entries carry the
     * relationship, so we resolve the named group(s) to DNs and OR-in
     * one {@see groupMembershipFilter()} clause per DN.
     *
     * In grouptree-style directories (RFC 2307 / posixGroup) the
     * relationship lives on the *group*, so we fetch the configured
     * member attribute from each matching group entry and OR-in
     * `(userkey=<value>)` clauses against the user search.
     *
     * @param string $groupMatch
     * @param string $filtermethod one of the FILTER_* constants
     * @return FilterInterface|null Null when no group matched.
     */
    protected function buildGroupMembershipClause($groupMatch, $filtermethod)
    {
        if ($this->resolveBulkGroupStrategy() === 'grouptree') {
            return $this->groupTreeMembershipClause($groupMatch, $filtermethod);
        }

        $groups = $this->getGroups($groupMatch, $filtermethod);
        $groupDNs = array_keys($groups);
        if (empty($groupDNs)) return null;

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
        return $or;
    }

    /**
     * Resolve `group_strategy=auto` without a specific user entry — used
     * by bulk operations like {@see getFilteredUsers()}. Falls back to
     * `grouptree` when a groupfilter is configured, otherwise `memberof`.
     *
     * @return string one of grouptree|memberof|none
     */
    protected function resolveBulkGroupStrategy()
    {
        $strategy = $this->config['group_strategy'] ?? 'auto';
        if ($strategy !== 'auto') return $strategy;
        return $this->config['groupfilter'] !== '' ? 'grouptree' : 'memberof';
    }

    /**
     * Read the member attribute from groups matching `$groupMatch` and
     * build a `(userkey=<value> OR ...)` filter against the user search.
     *
     * RFC 2307bis `member` attributes hold DNs rather than uids; we don't
     * try to support that here in v1.
     *
     * @param string $groupMatch
     * @param string $filtermethod
     * @return FilterInterface|null Null when no group matched or no
     *                              members were found.
     */
    protected function groupTreeMembershipClause($groupMatch, $filtermethod)
    {
        if (!$this->autoAuth()) return null;

        $memberAttr = $this->config['group_member_attr'];
        $groupFilter = Filters::and(
            Filters::equal('objectClass', $this->config['groupClass']),
            Filters::$filtermethod($this->config['groupkey'], $groupMatch)
        );

        $search = $this->applySearchScope(
            Operations::search($groupFilter, $this->config['groupkey'], $memberAttr),
            $this->config['grouptree'],
            $this->config['groupscope']
        );
        $paging = $this->ldap->paging($search);

        $members = [];
        while ($paging->hasEntries()) {
            try {
                $entries = $paging->getEntries();
            } catch (OperationException $e) {
                $this->fatal($e);
                return null;
            }
            foreach ($entries as $entry) {
                if (!$entry->has($memberAttr)) continue;
                foreach ($entry->get($memberAttr)->getValues() as $value) {
                    $members[] = $value;
                }
            }
        }
        $members = array_unique($members);
        if (empty($members)) return null;

        $or = Filters::or();
        foreach ($members as $value) {
            $or->add(Filters::equal($this->config['userkey'], $value));
        }
        return $or;
    }

    /**
     * Extract a group's short name from its DN by taking the value of the
     * first RDN. Uses the FreeDSx DN parser so escaped commas (`CN=Smith\,
     * John,OU=...`) and hex-escaped characters are handled per RFC 4514.
     *
     * @param string $dn
     * @return string
     */
    protected function dn2group($dn)
    {
        try {
            $value = (new Dn($dn))->getRdn()->getValue();
        } catch (\Exception $e) {
            return $this->cleanGroup($dn);
        }
        return $this->cleanGroup($this->unescapeRdnValue($value));
    }

    /**
     * Decode RFC 4514 escape sequences in an RDN value. Supports both the
     * `\XX` hex form and the `\X` single-character form.
     *
     * @param string $value
     * @return string
     */
    protected function unescapeRdnValue($value)
    {
        return (string)preg_replace_callback(
            '/\\\\([0-9A-Fa-f]{2}|.)/s',
            static function ($m) {
                return strlen($m[1]) === 2 ? chr(hexdec($m[1])) : $m[1];
            },
            $value
        );
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

    /**
     * Substitute %{key} placeholders in a filter template with values
     * from $placeholders.
     *
     * Mirrors authldap's long-standing template syntax. Unknown
     * placeholders are left in the output untouched; array values are
     * flattened to their first element; replacement values are
     * RFC 4515-escaped so user-supplied input cannot break out of the
     * filter.
     *
     * @param string $template
     * @param array $placeholders
     * @return string
     */
    protected function substitute($template, array $placeholders)
    {
        preg_match_all('/%\{([^}]+)\}/', $template, $matches, PREG_PATTERN_ORDER);
        foreach ($matches[1] as $key) {
            if (!array_key_exists($key, $placeholders)) continue;
            $value = $placeholders[$key];
            if (is_array($value)) $value = reset($value);
            $value = Attribute::escape((string)$value);
            $template = str_replace('%{' . $key . '}', $value, $template);
        }
        return $template;
    }
}
