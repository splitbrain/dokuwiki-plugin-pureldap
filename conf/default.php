<?php
/**
 * Default settings for the pureldap plugin
 *
 * @author Andreas Gohr <andi@splitbrain.org>
 */

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
$conf['page_size'] = 150;

$conf['sso'] = 0;
$conf['sso_charset'] = '';
