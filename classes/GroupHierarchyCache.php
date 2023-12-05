<?php

namespace dokuwiki\plugin\pureldap\classes;

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\Filters;

/**
 * Keeps a copy of all AD groups and provides recursive operations
 *
 * All groups are cached as full DN here
 */
class GroupHierarchyCache
{
    /** @var LdapClient */
    protected $ldap;

    /** @var array List of group DNs and their parent and children */
    protected $groupHierarchy;

    /**
     * GroupHierarchyCache constructor.
     *
     * @param LdapClient $ldap
     * @param bool $usefs Use filesystem caching?
     */
    public function __construct(LdapClient $ldap, $usefs)
    {
        $this->ldap = $ldap;

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

        $cachename = getcachename('grouphierarchy', '.pureldap-gch');
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
     * Load all group information from AD
     *
     * @return array
     */
    protected function getGroupList()
    {
        $filter = Filters::equal('objectCategory', 'group');
        $search = Operations::search($filter, 'memberOf', 'cn');
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
                if ($entry->has('memberOf')) {
                    $parents = $entry->get('memberOf')->getValues();
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
