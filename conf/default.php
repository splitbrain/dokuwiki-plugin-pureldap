<?php

/**
 * Default settings for the pureldap plugin
 *
 * @author Andreas Gohr <andi@splitbrain.org>
 */

$conf['directory_type'] = 'ad';

$conf['base_dn'] = '';
$conf['suffix'] = '';

$conf['servers'] = array();
$conf['port'] = '';

$conf['encryption'] = 'none';
$conf['validate'] = 'strict';

$conf['admin_username'] = '';
$conf['admin_password'] = '';

$conf['attributes'] = array();
$conf['primarygroup'] = 'Domain Users';
$conf['recursivegroups'] = 0;
$conf['expirywarn'] = 0;
$conf['usefscache'] = 1;
$conf['page_size'] = 150;

$conf['sso'] = 0;
$conf['sso_charset'] = '';

// Generic LDAP options (used when directory_type=ldap)
$conf['usertree'] = '';
$conf['grouptree'] = '';
$conf['userfilter'] = '';
$conf['groupfilter'] = '';
$conf['userscope'] = 'sub';
$conf['groupscope'] = 'sub';
$conf['userkey'] = 'uid';
$conf['groupkey'] = 'cn';
$conf['namekey'] = 'cn';
$conf['mailkey'] = 'mail';
$conf['userClass'] = 'inetOrgPerson';
$conf['groupClass'] = 'groupOfNames';
$conf['memberof_attr'] = 'memberOf';
$conf['group_member_attr'] = 'memberUid';
$conf['password_attr'] = 'userPassword';
$conf['binddn'] = '';
$conf['group_strategy'] = 'auto';
$conf['modPass'] = 1;
$conf['modPassPlain'] = 0;
