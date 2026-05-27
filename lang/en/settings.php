<?php
/**
 * english language file for pureldap plugin
 *
 * @author Andreas Gohr <andi@splitbrain.org>
 */

$lang['directory_type'] = 'Type of directory to authenticate against. Pick <code>ad</code> for Active Directory; <code>ldap</code> for OpenLDAP / FreeIPA / 389DS / any other RFC 4511 LDAP server.';
$lang['directory_type_o_ad'] = 'Active Directory';
$lang['directory_type_o_ldap'] = 'Generic LDAP';

$lang['base_dn'] = 'Your base DN. Eg. <code>DC=my,DC=domain,DC=org</code>';
$lang['suffix'] = '[AD only] Your account suffix. Eg. <code>my.domain.org</code>';

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
$lang['primarygroup'] = '[AD only] The name of your users primary group. Usually a localized version of <code>Domain Users</code>, eg. <code>Domänen-Benutzer</code>.';
$lang['recursivegroups'] = 'Correctly fetch nested group memberships for users? Increases LDAP requests and load on the AD server.';
$lang['expirywarn'] = 'Number of days before password expiry to warn the user. Set to 0 to disable.';
$lang['usefscache'] = 'Cache LDAP data on disk to speed up reoccuring queries. Check the <code>securitytimeout</code> for the maximum cache time.';
$lang['page_size'] = 'The maximum number of results to retrieve from the server in one request. Larger numbers speed up large queries but require more RAM.';

$lang['sso'] = 'Use Single-Sign-On (SSO). This requires the appropriate web server setup.';
$lang['sso_charset'] = 'If your webserver passes usernames in another charset than UTF-8, configure it here and make sure the iconv or mbstring extension is available.';

$lang['usertree'] = '[LDAP only] Base DN for user searches. Leave empty to search the entire directory.';
$lang['grouptree'] = '[LDAP only] Base DN for group searches.';
$lang['userfilter'] = '[LDAP only] LDAP filter template for finding a user. Placeholders: <code>%{user}</code>. Example: <code>(&amp;(uid=%{user})(objectClass=posixAccount))</code>';
$lang['groupfilter'] = '[LDAP only] LDAP filter template for finding the groups a user is in. Placeholders: <code>%{user}</code>, <code>%{dn}</code>, <code>%{gid}</code>. Example: <code>(&amp;(objectClass=posixGroup)(memberUid=%{user}))</code>';
$lang['userscope'] = '[LDAP only] Scope of the user search.';
$lang['userscope_o_sub'] = 'Entire subtree';
$lang['userscope_o_one'] = 'One level below the base';
$lang['userscope_o_base'] = 'Base entry only';
$lang['groupscope'] = '[LDAP only] Scope of the group search.';
$lang['groupscope_o_sub'] = 'Entire subtree';
$lang['groupscope_o_one'] = 'One level below the base';
$lang['groupscope_o_base'] = 'Base entry only';
$lang['userkey'] = '[LDAP only] Attribute that holds the user name. Comma-separated list allows fallback (e.g. <code>userPrincipalName,sAMAccountName</code>).';
$lang['groupkey'] = '[LDAP only] Attribute that holds the group name.';
$lang['namekey'] = '[LDAP only] Attribute(s) that hold the user\'s display name. Comma-separated list allows fallback.';
$lang['mailkey'] = '[LDAP only] Attribute that holds the user\'s email address.';
$lang['userClass'] = '[LDAP only] objectClass value used in the fallback user search filter when no userfilter is set.';
$lang['groupClass'] = '[LDAP only] objectClass value used to find group entries.';
$lang['memberof_attr'] = '[LDAP only] Attribute on a user entry that lists their group DNs. Default <code>memberOf</code>.';
$lang['group_member_attr'] = '[LDAP only] Attribute on a <em>group</em> entry that lists members in the RFC 2307 (posixGroup) model. Default <code>memberUid</code>. Used to find users that belong to a given group when <code>group_strategy=grouptree</code>.';
$lang['password_attr'] = '[LDAP only] Attribute that holds the user\'s password.';
$lang['binddn'] = '[LDAP only] DN template for direct user bind, e.g. <code>uid=%{user},ou=People,dc=example,dc=org</code>. Leave empty to search-then-bind using admin credentials.';
$lang['group_strategy'] = '[LDAP only] How to resolve a user\'s group memberships.';
$lang['group_strategy_o_auto'] = 'Auto (grouptree if groupfilter set, else memberOf)';
$lang['group_strategy_o_grouptree'] = 'Search the group tree using groupfilter (RFC 2307 / posixGroup)';
$lang['group_strategy_o_memberof'] = 'Read the memberOf attribute on the user';
$lang['group_strategy_o_none'] = 'Do not resolve groups';
$lang['modPass'] = '[LDAP only] Allow users to change their LDAP password through DokuWiki.';
$lang['modPassPlain'] = '[LDAP only] Send the new password in plain text (default: SSHA hash). Only enable if your directory handles its own password hashing.';
