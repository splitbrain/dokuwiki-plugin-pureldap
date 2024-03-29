<?php
/**
 * english language file for pureldap plugin
 *
 * @author Andreas Gohr <andi@splitbrain.org>
 */

$lang['base_dn'] = 'Your base DN. Eg. <code>DC=my,DC=domain,DC=org</code>';
$lang['suffix'] = 'Your account suffix. Eg. <code>my.domain.org</code>';

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

$lang['admin_username'] = 'A user with access to all other user\'s data. Needed for certain actions like sending subscription mails. Needs additional privileges for password resets.';
$lang['admin_password'] = 'The password of the above user.';

$lang['attributes'] = 'A comma separated list of additional attributes to fetch for users. May be used by some plugins.';
$lang['primarygroup'] = 'The name of your users primary group. Usually a localized version of <code>Domain Users</code>, eg. <code>Domänen-Benutzer</code>.';
$lang['recursivegroups'] = 'Correctly fetch nested group memberships for users? Increases LDAP requests and load on the AD server.';
$lang['expirywarn'] = 'Number of days before password expiry to warn the user. Set to 0 to disable.';
$lang['usefscache'] = 'Cache LDAP data on disk to speed up reoccuring queries. Check the <code>securitytimeout</code> for the maximum cache time.';
$lang['page_size'] = 'The maximum number of results to retrieve from the server in one request. Larger numbers speed up large queries but require more RAM.';

$lang['sso'] = 'Use Single-Sign-On (SSO). This requires the appropriate web server setup.';
$lang['sso_charset'] = 'If your webserver passes usernames in another charset than UTF-8, configure it here and make sure the iconv or mbstring extension is available.';
