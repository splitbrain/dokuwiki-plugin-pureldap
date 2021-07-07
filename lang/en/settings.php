<?php
/**
 * english language file for pureldap plugin
 *
 * @author Andreas Gohr <andi@splitbrain.org>
 */

$lang['base_dn'] = 'Your base DN. Eg. <code>DC=my,DC=domain,DC=org</code>';

$lang['servers'] = 'Comma-separated list of your LDAP/AD servers. Servers are tried in order until one connects.';
$lang['port'] = 'LDAP/AD server port. Empty for default port.';

$lang['encryption'] = 'What encryption should be used to talk to the servers?';
$lang['encryption_o_none'] = 'No encryption (default port 389)';
$lang['encryption_o_ssl'] = 'SSL (default port 636)';
$lang['encryption_o_tls'] = 'STARTTLS (default port 389)';

$lang['validate'] = 'Validate SSL certificates on encrypted connections?';
$lang['validate_o_strict'] = 'Strict validation';
$lang['validate_o_self'] = 'Allow self-signed certificates';
$lang['validate_o_none'] = 'Accept all certificates (no validation)';

$lang['admin_username'] = 'A privileged user with access to all other user\'s data. Needed for certain actions like sending subscription mails.';
$lang['admin_password'] = 'The password of the above user.';

$lang['attributes'] = 'A comma separated list of additional attributes to fetch for users. May be used by some plugins.';
$lang['page_size'] = 'The maximum number of results to retrieve from the server in one request. Larger numbers speed up large queries but require more RAM.';


