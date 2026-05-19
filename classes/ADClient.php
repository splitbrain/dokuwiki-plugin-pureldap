<?php

namespace dokuwiki\plugin\pureldap\classes;

use dokuwiki\Utf8\PhpString;
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\BindException;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Search\Filters;

/**
 * Active Directory specialisation of {@see LDAPClient}.
 *
 * Pre-seeds AD's standard schema as defaults (userPrincipalName +
 * sAMAccountName, displayName + Name, memberOf, objectClass=user/group)
 * and overrides the handful of methods that depend on real AD protocol:
 * UTF-16LE-encoded unicodePwd, FILETIME-based password expiry, the
 * primaryGroupID=513 "Domain Users" RID trick, and AD's bind error
 * sub-code table.
 */
class ADClient extends LDAPClient
{
    public const ADS_UF_DONT_EXPIRE_PASSWD = 0x10000;

    /** @inheritDoc */
    protected function prepareConfig($config)
    {
        // Seed AD-aware defaults; LDAPClient::prepareConfig will only fill
        // in keys that are still empty afterwards.
        $adDefaults = [
            'userkey' => 'userPrincipalName,sAMAccountName',
            'namekey' => 'displayName,Name',
            'mailkey' => 'mail',
            'groupkey' => 'cn',
            'userClass' => 'user',
            'groupClass' => 'group',
            'memberof_attr' => 'memberOf',
            'password_attr' => 'unicodePwd',
            'userfilter' =>
                '(&(objectClass=user)(|(sAMAccountName=%{user})(userPrincipalName=%{qualifieduser})))',
        ];
        foreach ($adDefaults as $key => $val) {
            if (!isset($config[$key]) || $config[$key] === '' || $config[$key] === []) {
                $config[$key] = $val;
            }
        }

        $config = parent::prepareConfig($config);

        $config['suffix'] = ltrim(PhpString::strtolower($config['suffix']), '@');
        $config['primarygroup'] = $this->cleanGroup($config['primarygroup']);

        return $config;
    }

    /**
     * A non-null $oldpass marks a self-service password change (the user
     * changing their own password). AD requires this to be expressed as a
     * delete-then-add modify; a simple replace only works when acting as
     * a privileged admin (when $oldpass is null).
     *
     * @inheritDoc
     */
    protected function applyPasswordChange(Entry $entry, $newpass, $oldpass)
    {
        $attr = $this->passwordAttribute();
        if ($oldpass) {
            $entry->remove($attr, $this->encodePassword($oldpass));
            $entry->add($attr, $this->encodePassword($newpass));
        } else {
            $entry->set($attr, $this->encodePassword($newpass));
        }
    }

    /**
     * AD will only accept password changes over an encrypted connection.
     *
     * @inheritDoc
     */
    public function canModPass()
    {
        return $this->config['encryption'] !== 'none';
    }

    /** @inheritDoc */
    public function supportsPasswordExpiry()
    {
        return true;
    }

    /** @inheritDoc */
    public function cleanUser($user)
    {
        return $this->simpleUser($user);
    }

    /** @inheritDoc */
    protected function prepareBindUser($user)
    {
        return $this->qualifiedUser($user);
    }

    /** @inheritDoc */
    protected function prepareAdminBindUser($admin)
    {
        return $this->qualifiedUser($admin);
    }

    /**
     * AD always uses UPN/principal-name binding, never search-then-bind.
     *
     * @inheritDoc
     */
    protected function usesDirectBind()
    {
        return true;
    }

    /**
     * AD looks up users by either sAMAccountName (short form) or
     * userPrincipalName (long form with @suffix); the seeded userfilter
     * encodes that as two parallel filter clauses. This hook supplies
     * the values to substitute for each placeholder.
     *
     * @inheritDoc
     */
    protected function userSearchPlaceholders($username)
    {
        return [
            'user' => $this->simpleUser($username),
            'qualifieduser' => $this->qualifiedUser($username),
        ];
    }

    /** @inheritDoc */
    protected function userAttributes()
    {
        $attr = parent::userAttributes();
        $attr[] = new Attribute('primaryGroupID');
        $attr[] = new Attribute('pwdlastset');
        $attr[] = new Attribute('useraccountcontrol');
        return $attr;
    }

    /**
     * pwdlastset is a Windows FILETIME: 100-nanosecond intervals since
     * 1601-01-01. Convert to Unix epoch seconds.
     *
     * @inheritDoc
     */
    protected function extractLastpwd(Entry $entry)
    {
        $lastChange = $this->attr2str($entry->get('pwdlastset'));
        if (!$lastChange) return 0;
        $lastChange = (int)substr($lastChange, 0, -7);
        return $lastChange - 11_644_473_600;
    }

    /** @inheritDoc */
    protected function extractExpires(Entry $entry)
    {
        return !($this->attr2str($entry->get('useraccountcontrol')) & self::ADS_UF_DONT_EXPIRE_PASSWD);
    }

    /**
     * AD's primary group membership is encoded as a RID in primaryGroupID
     * rather than a memberOf entry. RID 513 = "Domain Users".
     *
     * @inheritDoc
     */
    protected function additionalGroups(Entry $userentry)
    {
        $gid = $userentry->get('primaryGroupID')->firstValue();
        if ($gid == 513) {
            return [$this->cleanGroup($this->config['primarygroup'])];
        }
        return [];
    }

    /**
     * When searching members of the primary group, AD only has them via
     * the primaryGroupID RID — they have no memberOf entry for it.
     *
     * @inheritDoc
     */
    protected function groupMembershipFilter($groupDn)
    {
        if ($this->dn2group($groupDn) === $this->config['primarygroup']) {
            return Filters::equal('primaryGroupID', 513);
        }
        return parent::groupMembershipFilter($groupDn);
    }

    /**
     * Queries the maximum password age from the AD server
     *
     * Note: we do not check if passwords actually are set to expire here.
     * This is encoded in the lower 32bit of the returned 64bit integer
     * (see link below). We do not check this because it would require us
     * to actually do large integer math and we can simply assume it's
     * enabled when the age check was requested in DokuWiki configuration.
     *
     * @link http://msdn.microsoft.com/en-us/library/ms974598.aspx
     * @param bool $useCache should a filesystem cache be used if available?
     * @return int The maximum password age in seconds
     */
    public function getMaxPasswordAge($useCache = true)
    {
        global $conf;
        $cachename = getCacheName('maxPwdAge', '.pureldap-maxPwdAge');
        $cachetime = @filemtime($cachename);

        if ($useCache && $cachetime && (time() - $cachetime) < $conf['auth_security_timeout']) {
            return (int)file_get_contents($cachename);
        }

        if (!$this->autoAuth()) return 0;

        $attr = new Attribute('maxPwdAge');
        try {
            $entry = $this->ldap->read($this->getConf('base_dn'), [$attr]);
        } catch (OperationException $e) {
            $this->fatal($e);
            return 0;
        }
        if (!$entry) return 0;
        $maxPwdAge = $entry->get($attr)->firstValue();

        // MS returns 100 nanosecond intervals, we want seconds. Operate on
        // strings to avoid integer overflow; trim the leading minus sign so
        // the result is positive before casting.
        $maxPwdAge = (int)ltrim(substr($maxPwdAge, 0, -7), '-');

        file_put_contents($cachename, $maxPwdAge);
        return $maxPwdAge;
    }

    /**
     * Translate Active Directory bind error sub-codes into a localisable
     * message key.
     *
     * AD encodes specific failure reasons (account disabled, password
     * expired, etc.) in the bind error text as "data XXX". See
     * https://ldapwiki.com/wiki/Wiki.jsp?page=Common%20Active%20Directory%20Bind%20Errors
     *
     * @inheritDoc
     */
    public function translateBindException(\Exception $e)
    {
        $bindErrors = [
            '52f' => 'ERROR_ACCOUNT_RESTRICTION',
            '530' => 'ERROR_INVALID_LOGON_HOURS',
            '531' => 'ERROR_INVALID_WORKSTATION',
            '532' => 'ERROR_PASSWORD_EXPIRED',
            '533' => 'ERROR_ACCOUNT_DISABLED',
            '701' => 'ERROR_ACCOUNT_EXPIRED',
            '773' => 'ERROR_PASSWORD_MUST_CHANGE',
        ];

        if (
            !($e instanceof BindException) ||
            $e->getCode() !== 49 ||
            !preg_match('/ data ([0-9a-f]{3})/', $e->getMessage(), $matches)
        ) {
            return null;
        }

        $code = $matches[1];
        if (!isset($bindErrors[$code])) return null;

        return [
            'key' => $bindErrors[$code],
            'allowReset' => $code === '532' || $code === '773',
        ];
    }

    /**
     * userPrincipalName in the form &lt;user&gt;@&lt;suffix&gt;
     *
     * @param string $user
     * @return string
     */
    protected function qualifiedUser($user)
    {
        $user = $this->simpleUser($user);
        if (!$this->config['suffix']) {
            $this->error('No account suffix set. Logins may fail.', __FILE__, __LINE__);
        }
        return $user . '@' . $this->config['suffix'];
    }

    /**
     * Strip any UPN suffix or DOMAIN\ prefix and lowercase. The result
     * should match the user's sAMAccountName.
     *
     * @param string $user
     * @return string
     */
    protected function simpleUser($user)
    {
        $user = PhpString::strtolower($user);
        $user = preg_replace('/@.*$/', '', $user);
        $user = preg_replace('/^.*\\\\/', '', $user);
        return $user;
    }

    /**
     * Encode a password for AD's unicodePwd attribute (UTF-16LE bytes of
     * the quoted password).
     *
     * @inheritDoc
     */
    protected function encodePassword($password)
    {
        $password = "\"" . $password . "\"";

        if (function_exists('iconv')) {
            $adpassword = iconv('UTF-8', 'UTF-16LE', $password);
        } elseif (function_exists('mb_convert_encoding')) {
            $adpassword = mb_convert_encoding($password, "UTF-16LE", "UTF-8");
        } else {
            // ASCII7-only fallback
            $adpassword = '';
            for ($i = 0; $i < strlen($password); $i++) {
                $adpassword .= "$password[$i]\000";
            }
        }
        return $adpassword;
    }
}
