<?php

namespace dokuwiki\plugin\pureldap\classes;

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Search\Filters;

/**
 * Keeps a copy of all groups and provides recursive operations.
 *
 * All groups are cached by their full DN. Active Directory and generic LDAP
 * servers expose group hierarchies via the same `memberOf` chain pattern;
 * this class is parameterised so that subclasses of {@see Client} can supply
 * their own search filter and attribute names.
 */
class GroupHierarchyCache
{
    /** @var LdapClient */
    protected $ldap;

    /** @var FilterInterface */
    protected $filter;

    /** @var string */
    protected $parentAttr;

    /** @var string */
    protected $nameAttr;

    /** @var string */
    protected $cacheKey;

    /** @var array List of group DNs and their parent and children */
    protected $groupHierarchy;

    /**
     * @param LdapClient $ldap
     * @param bool $usefs Use filesystem caching?
     * @param FilterInterface|null $filter Search filter used to enumerate groups;
     *        defaults to AD's `(objectCategory=group)` which also matches generic
     *        LDAP installs that don't set objectCategory explicitly.
     * @param string $parentAttr Multi-valued attribute on each group entry that
     *        lists the parent groups. Defaults to the standard `memberOf`.
     * @param string $nameAttr Attribute holding the group's canonical name.
     *        Currently informational; the cache keys off DN.
     * @param string $cacheKey Filesystem cache namespace.
     */
    public function __construct(
        LdapClient $ldap,
        $usefs,
        FilterInterface $filter = null,
        $parentAttr = 'memberOf',
        $nameAttr = 'cn',
        $cacheKey = 'grouphierarchy'
    ) {
        $this->ldap = $ldap;
        $this->filter = $filter ?? Filters::equal('objectCategory', 'group');
        $this->parentAttr = $parentAttr;
        $this->nameAttr = $nameAttr;
        $this->cacheKey = $cacheKey;

        if ($usefs) {
            $this->groupHierarchy = $this->getCachedGroupList();
        } else {
            $this->groupHierarchy = $this->getGroupList();
        }
    }

    /**
     * Use a file system cached version of the group hierarchy
     *
     * The cache expires after $conf['auth_security_timeout']
     *
     * @return array
     */
    protected function getCachedGroupList()
    {
        global $conf;

        $cachename = getcachename($this->cacheName(), '.pureldap-gch');
        $cachetime = @filemtime($cachename);

        // valid file system cache? use it
        if ($cachetime && (time() - $cachetime) < $conf['auth_security_timeout']) {
            return json_decode(file_get_contents($cachename), true, 512, JSON_THROW_ON_ERROR);
        }

        // get fresh data and store in cache
        $groups = $this->getGroupList();
        file_put_contents($cachename, json_encode($groups, JSON_THROW_ON_ERROR));
        return $groups;
    }

    /**
     * Filesystem cache key. Includes a short hash of the filter and parent
     * attribute so different directory layouts don't share cache files.
     *
     * @return string
     */
    protected function cacheName()
    {
        $signature = substr(md5($this->filter->toString() . '|' . $this->parentAttr), 0, 8);
        return $this->cacheKey . '-' . $signature;
    }

    /**
     * Load all group information from the directory.
     *
     * @return array
     */
    protected function getGroupList()
    {
        $search = Operations::search($this->filter, $this->parentAttr, $this->nameAttr);
        $paging = $this->ldap->paging($search);

        $groups = [];

        while ($paging->hasEntries()) {
            try {
                $entries = $paging->getEntries();
            } catch (ProtocolException $e) {
                return $groups; // return what we have
            }
            /** @var Entry $entry */
            foreach ($entries as $entry) {
                $dn = (string)$entry->getDn();
                $groups[$dn] = [];
                if ($entry->has($this->parentAttr)) {
                    $parents = $entry->get($this->parentAttr)->getValues();
                    $groups[$dn]['parents'] = $parents;
                    foreach ($parents as $parent) {
                        $groups[$parent]['children'][] = $dn;
                    }
                }
            }
        }
        return $groups;
    }

    /**
     * Recursive method to get all children or parents
     *
     * @param string $group
     * @param string $type
     * @param array $data list to fill
     */
    protected function getHierarchy($group, $type, &$data)
    {
        if (empty($this->groupHierarchy[$group][$type])) return;

        $parents = $this->groupHierarchy[$group][$type];
        foreach ($parents as $parent) {
            if (in_array($parent, $data)) continue; // we did this one already
            $data[] = $parent;
            $this->getHierarchy($parent, $type, $data);
        }
    }

    /**
     * Get all parents of a group
     *
     * @param string $group
     * @return string[]
     */
    public function getParents($group)
    {
        $parents = [];
        $this->getHierarchy($group, 'parents', $parents);
        return $parents;
    }

    /**
     * Get all children of a group
     *
     * @param string $group
     * @return string[]
     */
    public function getChildren($group)
    {
        $children = [];
        $this->getHierarchy($group, 'children', $children);
        return $children;
    }
}
