<?php

namespace dokuwiki\plugin\pureldap\classes;

use dokuwiki\Utf8\PhpString;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\Filters;

class GroupHierarchyCache
{
    protected $ldap;

    protected $groupHierarchy;

    public function __construct(LdapClient $ldap)
    {
        $this->ldap = $ldap;

        $this->groupHierarchy = $this->getGroupList();
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
     * @return string[]
     */
    protected function getHierarchy($group, $type)
    {
        $dependents = []; // either parents or children
        if (empty($this->groupHierarchy[$group][$type])) return $dependents;

        $dependents = $this->groupHierarchy[$group][$type];
        foreach ($dependents as $parent) {
            $dependents = array_merge($dependents, $this->getHierarchy($parent, $type));
        }

        return $dependents;
    }

    /**
     * Get all parents of a group
     *
     * @param string $group
     * @return string[]
     */
    public function getParents($group) {
        return $this->getHierarchy($group, 'parents');
    }

    /**
     * Get all children of a group
     *
     * @param string $group
     * @return string[]
     */
    public function getChildren($group) {
        return $this->getHierarchy($group, 'children');
    }
}

