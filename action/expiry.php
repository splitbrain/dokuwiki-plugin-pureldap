<?php

use dokuwiki\Extension\ActionPlugin;
use dokuwiki\Extension\EventHandler;
use dokuwiki\Extension\Event;

/**
 * DokuWiki Plugin pureldap (Action Component)
 *
 * @license GPL 2 http://www.gnu.org/licenses/gpl-2.0.html
 * @author  Andreas Gohr <andi@splitbrain.org>
 */
class action_plugin_pureldap_expiry extends ActionPlugin
{
    /** @inheritDoc */
    public function register(EventHandler $controller)
    {
        global $conf;
        // the plugin might be enabled, but not used
        if ($conf['authtype'] !== 'authpureldap') return;

        $controller->register_hook('DOKUWIKI_STARTED', 'AFTER', $this, 'handlePasswordExpiry');
    }

    /**
     * Handle password expiry
     *
     * On each page load, check if the user's password is about to expire and display a warning if so.
     *
     * @see https://www.dokuwiki.org/devel:events:DOKUWIKI_STARTED
     * @param Event $event Event object
     * @param mixed $param optional parameter passed when event was registered
     * @return void
     */
    public function handlePasswordExpiry(Event $event, $param)
    {
        global $auth;
        global $ID;
        global $lang;
        global $INPUT;

        $user = $INPUT->server->str('REMOTE_USER');
        if (!$user) return; // no user logged in
        $userdata = $auth->getUserData($user);

        $warn = $auth->client->getConf('expirywarn'); // days before expiry to warn
        if (!$warn) return; // no warning configured
        $max = $auth->client->getMaxPasswordAge(); // max password age in seconds
        if (!$max) return; // no max password age configured
        $lastchange = $userdata['lastpwd'] ?? 0; // last password change timestamp
        if (!$lastchange) return;
        $expires = $userdata['expires'] ?? false; // password expires
        if (!$expires) return;

        $warn = $warn * 24 * 60 * 60; // convert to seconds
        $expiresin = ($lastchange + $max) - time(); // seconds until password expires
        if ($expiresin > $warn) return; // not yet time to warn
        $days = ceil($expiresin / (24 * 60 * 60)); // days until password expires

        // prepare and show message
        $msg = sprintf($this->getLang('pwdexpire'), $days);
        if ($auth->canDo('modPass')) {
            $url = wl($ID, ['do' => 'profile']);
            $msg .= ' <a href="' . $url . '">' . $lang['btn_profile'] . '</a>';
        }
        msg($msg);
    }
}
