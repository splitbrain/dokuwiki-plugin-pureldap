<?php

/**
 * Options for the pureldap plugin
 *
 * @author Andreas Gohr <andi@splitbrain.org>
 */

$meta['directory_type'] = array('multichoice', '_choices' => array('ad', 'ldap'));

$meta['base_dn'] = array('string');
$meta['suffix'] = array('string');

$meta['servers'] = array('array');
$meta['port'] = array('string');

$meta['encryption'] = array('multichoice', '_choices' => array('none', 'ssl', 'tls'));
$meta['validate'] = array('multichoice', '_choices' => array('strict', 'self', 'none'));

$meta['admin_username'] = array('string');
$meta['admin_password'] = array('password');

$meta['attributes'] = array('array');
$meta['primarygroup'] = array('string');
$meta['recursivegroups'] = array('onoff');
$meta['expirywarn'] = array('numeric', '_min' => 0);
$meta['usefscache'] = array('onoff');
$meta['page_size'] = array('numeric', '_min' => 1);

$meta['sso'] = array('onoff');
$meta['sso_charset'] = array('string');

$meta['usertree'] = array('string');
$meta['grouptree'] = array('string');
$meta['userfilter'] = array('string');
$meta['groupfilter'] = array('string');
$meta['userscope'] = array('multichoice', '_choices' => array('sub', 'one', 'base'));
$meta['groupscope'] = array('multichoice', '_choices' => array('sub', 'one', 'base'));
$meta['userkey'] = array('string');
$meta['groupkey'] = array('string');
$meta['namekey'] = array('string');
$meta['mailkey'] = array('string');
$meta['userClass'] = array('string');
$meta['groupClass'] = array('string');
$meta['memberof_attr'] = array('string');
$meta['group_member_attr'] = array('string');
$meta['password_attr'] = array('string');
$meta['binddn'] = array('string');
$meta['group_strategy'] = array('multichoice', '_choices' => array('auto', 'grouptree', 'memberof', 'none'));
$meta['modPass'] = array('onoff');
$meta['modPassPlain'] = array('onoff');
