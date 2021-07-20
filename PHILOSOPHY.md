# LDAP/AD Auth in DokuWiki

## Current State

DokuWiki includes two plugins that can authenticate users via the LDAP protocol: [authldap](https://www.dokuwiki.org/plugin:authldap) and [authad](https://www.dokuwiki.org/plugin:authad). Despite both plugins doing similar things, both are completely separate and share no code.

While authldap uses the PHP LDAP extension directly, authad makes use of the  [adLDAP](https://github.com/adldap/adLDAP) library. There are multiple versions of this library - all slightly incompatible with each other. The authad Plugin uses version 1. The library abstracts away all the LDAP specifics, implements weird Microsoft quirks and makes it easier to configure AD access than doing it manually. However it also limits the ability to configure customize the access to unusual AD setups.

The table below shows the features of both plugins

|                                  | authldap |          authad          |
|:--------------------------------:|:--------:|:------------------------:|
| Server Support                   |    any   | MS Active Directory only |
| Single Sign On                   |    no    |       Kerberos/NTLM      |
| Change Password                  |    no    |            yes           |
| Warn on expiring password        |    no    |            yes           |
| Multi-Domain Support             |    no    |            yes           |
| Fetch additional attributes      |    yes   |            yes           |
| Custom Attribut-Mapping          |    yes   |            no            |
| Full control on all LDAP queries |    yes   |            no            |

Both plugins basically provide the same base features: authenticate users against an LDAP server and make the groups available for ACL management.

Both plugins share a few shortcomings when it comes to performance. This is especially notable when user data of many users needs to be queried.

1. All user data has to be queried individually. Whenever a plugin requires the members of a given group, an additional query has to be made to fetch their user data for each member.
2. Already queried user data isn't cached. So if a user's info is used several times, several LDAP queries have to be executed.
3. The performance of the PHP LDAP extension itself isn't stellar either.

There are also quality problems in both plugins

1. the adLDAP library is no longer maintained
2. both plugins differ in functionality
3. there is some code duplication between the plugins
4. no automated tests

## pureLDAP

The pureLDAP plugin tries to remedy those issues.

### requirements

For creating a new DokuWiki LDAP plugin, the following reuirements should be met:

1. single code base for LDAP and AD connections
2. strong caching for queried data
3. implement bulk queries
4. implement the full feature set of both old plugins

Implementing all those features does not have to be done right away. It makes sense to first focus on one aspect (eg. AD connectivity) and implement features step by step.

### current state

A first prototype with focusing on Active Directory was created in April 2020. Connectivity is based on the pure PHP implementation of the LDAP protocol provided in the [FreeDSx LDAP](https://github.com/FreeDSx/LDAP).

It implements all the basic features needed to authenticate users via AD and has support for bulk queries. Automated tests run against a AD Vagrant setup.

Funding to implement caching and code clean up has since been received and implemented.

In some preliminary tests it already performed much better than authAD and should be good enough to replace simple AD setups.

### next steps

The [Github Project: Full Feature Set](https://github.com/splitbrain/dokuwiki-plugin-pureldap/projects/1) provides a rough overview on the next steps that are needed to make the plugin an adequate replecement for the two old plugins.

Now here's the thing. Me as a private person has absolutely no use for LDAP or AD connectivity. Setting up test servers etc. is a huge drag. There is really nothing here that motivates except that it would be nice to have.

So instead of me implementing this in my spare time, it makes more sense for [CosmoCode](https://www.cosmocode.de) to implement this. Or to rephrase it: it makes more sense for me to create this while being paid to do so.

If you want to make use of more performant LDAP or AD connectivity in DokuWiki and have the company ressources to fund that. Please get in contact at [dokuwiki@cosmocode.de](mailto:dokuwiki@cosmocode.de).

