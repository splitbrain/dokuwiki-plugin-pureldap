<?php

namespace dokuwiki\plugin\pureldap\classes;

/**
 * Filter-template substitution for LDAP search filters.
 *
 * Mirrors the authldap plugin's long-standing template syntax:
 * placeholders of the form `%{name}` are replaced by the value of the
 * matching key in the provided array. Replacement values are
 * RFC 4515-escaped before substitution so user-supplied input cannot
 * break out of the filter.
 *
 * The escape rule covers the five characters LDAP requires to be
 * escaped (`*`, `(`, `)`, `\`, NUL) plus other control bytes, each
 * encoded as a `\xx` hex pair. See RFC 4515 §3.
 */
class FilterTemplate
{
    /**
     * Substitute %{key} placeholders with values from $placeholders.
     *
     * Unknown placeholders are left in the output untouched, matching
     * authldap's existing behaviour. Array values are flattened to their
     * first element.
     *
     * @param string $template
     * @param array $placeholders
     * @return string
     */
    public static function substitute($template, array $placeholders)
    {
        preg_match_all('/%\{([^}]+)\}/', $template, $matches, PREG_PATTERN_ORDER);
        foreach ($matches[1] as $key) {
            if (!array_key_exists($key, $placeholders)) continue;
            $value = $placeholders[$key];
            if (is_array($value)) $value = reset($value);
            $value = self::filterEscape((string)$value);
            $template = str_replace('%{' . $key . '}', $value, $template);
        }
        return $template;
    }

    /**
     * Escape a value for safe inclusion in an LDAP filter.
     *
     * Ported from authldap (Net::LDAP::Util::escape_filter_value).
     *
     * @param string $value
     * @return string
     */
    public static function filterEscape($value)
    {
        return preg_replace_callback(
            '/([\x00-\x1F\*\(\)\\\\])/',
            static fn($matches) => '\\' . implode('', unpack('H2', $matches[1])),
            $value
        );
    }
}
