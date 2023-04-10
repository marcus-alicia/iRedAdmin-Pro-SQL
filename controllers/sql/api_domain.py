# Author: Zhang Huangbin <zhb@iredmail.org>

import web

from controllers.utils import api_render

from libs.sqllib import SQLWrap, decorators
from libs.sqllib import domain as sql_lib_domain
from libs.sqllib import general as sql_lib_general
from libs.sqllib import api_utils

session = web.config.get('_session')


class APIDomains:
    @decorators.api_require_admin_login
    def GET(self):
        """Get all managed domains.

        curl -X GET -i -b cookie.txt https://<server>/api/domains
        curl -X GET -i -b cookie.txt https://<server>/api/domains?name_only=
        curl -X GET -i -b cookie.txt https://<server>/api/domains?name_only=&disabled_only=

        Optional parameters:

        @name_only - Return only domain names, no profiles.
        @disabled_only - Return profiles of disabled domains.

        Values of above 2 parameters don't matter at all, for example, these 2
        values are the same: `name_only=`, `name_only=yes`.
        """
        name_only = False
        disabled_only = False

        form = web.input()
        if 'name_only' in form:
            name_only = True

        if 'disabled_only' in form:
            disabled_only = True

        qr = sql_lib_domain.get_all_managed_domains(name_only=name_only, disabled_only=disabled_only)
        if qr[0]:
            if name_only:
                return api_render((True, qr[1]))
            else:
                profiles = {}
                for i in qr[1]:
                    domain = str(i.domain).lower()
                    profiles[domain] = api_utils.export_sql_record(record=i)

                return api_render((True, profiles))
        else:
            return api_render(qr)


class APIDomain:
    @decorators.api_require_domain_access
    def GET(self, domain):
        """Export SQL record of mail domain as a dict.

        curl -X GET -i -b cookie.txt https://<server>/api/domain/<domain>
        """
        domain = str(domain).lower()

        _wrap = SQLWrap()
        conn = _wrap.conn

        qr = sql_lib_domain.profile(domain=domain)
        if qr[0]:
            profile = api_utils.export_sql_record(record=qr[1])

            #
            # Get all alias domains
            #
            _qr = sql_lib_domain.get_all_alias_domains(domain=domain,
                                                       name_only=True,
                                                       conn=conn)
            if _qr[0]:
                profile['alias_domains'] = _qr[1]

            #
            # Get per-domain sender dependent relayhost
            #
            (_status, _result) = sql_lib_general.get_sender_relayhost(sender='@' + domain)
            if _status:
                profile['relayhost'] = _result

            #
            # Get allocated domain quota
            #
            _quota = sql_lib_domain.get_allocated_domain_quota(domains=[domain])
            profile['allocated_quota'] = _quota

            return api_render((True, profile))
        else:
            return api_render(qr)

    @decorators.api_require_global_admin
    def POST(self, domain):
        """Create a new domain.

        curl -X POST -i -b cookie.txt -d "defaultQuota=1024" https://<server>/api/domain/<new_domain>

        Parameters:

        @name - the short description of this domain name. e.g. company name.
        @quota - per-domain mailbox quota, in MB.
        @language - default preferred language for new user.
                    e.g. en_US for English, de_DE for Deutsch.
        @transport - per-domain transport
        @defaultQuota - default mailbox quota for new user.
        @maxUserQuota - Max mailbox quota of a single mail user
        @numberOfUsers - Max number of mail user accounts
        @numberOfAliases - Max number of mail alias accounts
        """
        form = web.input()
        form['domainName'] = domain
        form['cn'] = form.get('name')

        form['preferredLanguage'] = form.get('language', '')
        form['mtaTransport'] = form.get('transport', '')

        form['domainQuota'] = form.get('quota')
        form['domainQuotaUnit'] = 'MB'

        qr = sql_lib_domain.add(form=form)
        return api_render(qr)

    @decorators.api_require_domain_access
    def DELETE(self, domain, keep_mailbox_days=0):
        """Delete an existing mail domain.

        curl -X DELETE -i -b cookie.txt https://<server>/api/domain/<domain>
        curl -X DELETE -i -b cookie.txt https://<server>/api/domain/<domain>/keep_mailbox_days/<days>
        """
        qr = sql_lib_domain.delete_domains(domains=[domain], keep_mailbox_days=keep_mailbox_days)
        return api_render(qr)

    @decorators.api_require_domain_access
    def PUT(self, domain):
        """Update domain profile.

        curl -X PUT -i -b cookie.txt -d "var=<value>" https://<server>/api/domain/<domain>
        curl -X PUT -i -b cookie.txt -d "var=<value>&var2=<value2>" https://<server>/api/domain/<domain>

        :param domain: domain name.

        Form parameters:

        `name`: the short company/orgnization name
        `accountStatus`: enable or disable domain. possible value is: active, disabled.
        `quota`: Per-domain mailbox quota
        `transport`: Per-domain transport

        `language`: default preferred language for new user.
                    e.g. en_US for English, de_DE for Deutsch.

        `minPasswordLength`: Minimal password length
        `maxPasswordLength`: Maximum password length

        `defaultQuota`: default mailbox quota for new user.
        `maxUserQuota`: Max mailbox quota of a single mail user

        `numberOfUsers`: Max number of mail user accounts
        `numberOfAliases`: Max number of mail alias accounts

        `senderBcc`: set bcc address for outgoing emails
        `recipientBcc`: set bcc address for incoming emails

        `catchall`: set per-domain catch-all account.
                    catchall account is a list of email address which will
                    receive emails sent to non-existing address under same
                    domain

        `outboundRelay`: relay outgoing emails to specified host

        `addService`: enable new services. Multiple services must be separated by comma.
        `removeService`: disable existing services. Multiple services must be separated by comma.
        `services`: reset all services. If empty, all existing services will be removed.

        `disableDomainProfile`: disable given domain profiles. Normal admin
                                cannot view and update disabled profiles in
                                domain profile page.
        `enableDomainProfile`: enable given domain profiles. Normal admin
                               can view and update disabled profiles in
                               domain profile page.
        `disableUserProfile`: disable given user profiles. Normal admin
                              cannot view and update disabled profiles in
                              user profile page.
        `enableUserProfile`: enable given domain profiles. Normal admin
                             can view and update disabled profiles in
                             user profile page.
        `disableUserPreference`: disable given user preferences in
                                 self-service page. Normal mail user cannot
                                 view and update disabled preferences.
        `enableUserPreference`: disable given user preferences in
                                self-service page. Normal mail user can
                                view and update disabled preferences.
        `aliasDomains`: remove all existing alias domains and add given
                        domains as alias domains. Multiple domains must be
                        separated by comma.
        `addAliasDomain`: add new alias domains. Multiple domains must be
                          separated by comma.
        `removeAliasDomain`: remove existing alias domains. Multiple
                             domains must be separated by comma.
        """
        form = web.input()
        qr = sql_lib_domain.api_update_profile(domain=domain, form=form)
        return api_render(qr)


class APIDomainAdmin:
    @decorators.api_require_domain_access
    def GET(self, domain):
        """List all existing domain admins.

        curl -X GET -i -b cookie.txt https://<server>/api/domain/admins/<domain>
        """
        qr = sql_lib_domain.get_domain_admin_addresses(domain=domain)
        return api_render(qr)

    @decorators.api_require_domain_access
    def PUT(self, domain):
        """Update domain admins.

        curl -X PUT -i -b cookie.txt -d "var=<value>[,<value2>,...]" https://<server>/api/domain/admins/<domain>

        Parameters:

        @addAdmin - Add new domain admin. Multiple admins must be separated by comma.
        @removeAdmin - Remove existing domain admin. Multiple admins must be separated by comma.
        @removeAllAdmin - Remove all existing domain admins.
        """
        form = web.input()
        qr = sql_lib_domain.api_update_domain_admins(domain=domain, form=form)
        return api_render(qr)
