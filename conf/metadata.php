<?php
/**
 * Options for the pureldap plugin
 *
 * @author Andreas Gohr <andi@splitbrain.org>
 */

$meta['base_dn'] = array('string');
$meta['suffix'] = array('string');

$meta['servers'] = array('array');
$meta['port'] = array('string');

$meta['encryption'] = array('multichoice', '_choices' => array('none', 'ssl', 'tls'));
$meta['validate'] = array('multichoice', '_choices' => array('strict', 'self', 'none'));

$meta['admin_username'] = array('string');
$meta['admin_password'] = array('password');

$meta['attributes'] = array('array');
$meta['page_size'] = array('numeric', '_min' => 1);


