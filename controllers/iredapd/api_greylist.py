import web
from controllers.utils import api_render
from libs import iredutils
from libs.iredapd import greylist as lib_greylist

import settings

if settings.backend == 'ldap':
    from libs.ldaplib import decorators
else:
    from libs.sqllib import decorators


def convert_greylist_setting_to_api_json(greylist_setting=None):
    """Return dict with simplified information as API result."""
    if not greylist_setting:
        greylist_setting = {}

    _status = greylist_setting.get('active', 'inherit')

    status = 'inherit'
    if _status == 1:
        status = 'enabled'
    elif _status == 0:
        status = 'disabled'

    return api_render((True, {'status': status}))


class APIAllSettings:
    @decorators.api_require_global_admin
    def GET(self):
        """Get all existing greylisting settings.

        curl -X GET -i -b cookie.txt https://<server>/api/greylisting/all
        """
        s = lib_greylist.get_all_greylist_settings()

        _all_settings = {}
        for i in s:
            _sender = str(i.sender).lower()
            _account = str(i.account).lower()
            _active = int(i.active)

            _setting = {'sender': _sender,
                        'account': _account}

            if _active == 1:
                _setting['status'] = 'enabled'
            else:
                _setting['status'] = 'disabled'

            if _account in _all_settings:
                _all_settings[_account] += [_setting]
            else:
                _all_settings[_account] = [_setting]

        return api_render((True, _all_settings))


class APIGlobalSetting:
    @decorators.api_require_global_admin
    def GET(self):
        """Get global greylisting setting.

        curl -X GET -i -b cookie.txt https://<server>/api/greylisting/global
        """
        s = lib_greylist.get_greylist_setting(account='@.')

        # If no greylisting setting, mark it as explicitly disabled.
        if not s:
            s = {'active': 0}

        return convert_greylist_setting_to_api_json(s)

    @decorators.api_require_global_admin
    def POST(self):
        """Set global greylisting setting.

        curl -X POST -i -b cookie.txt -d "status=enable" https://<server>/api/greylisting/global

        Required parameters:

        @status -- Explicitly enable or disable greylisting globally.
                   Possible values: enable, disable.
        """
        form = web.input(_unicode=False)

        enable = True
        if form.get('status') == 'disable':
            enable = False

        qr = lib_greylist.enable_disable_greylist_setting(account='@.', enable=enable)
        return api_render(qr)


class APIDomainSetting:
    @decorators.api_require_domain_access
    def GET(self, domain):
        """Get per-domain greylisting setting.

        curl -X GET -i -b cookie.txt https://<server>/api/greylisting/<domain>
        """
        domain = str(domain).lower()

        s = lib_greylist.get_greylist_setting(account='@' + domain)
        return convert_greylist_setting_to_api_json(s)

    @decorators.api_require_domain_access
    def POST(self, domain):
        """Set per-domain greylisting setting.

        curl -X POST -i -b cookie.txt -d "status=enable" https://<server>/api/greylisting/<domain>

        Required parameters:

        @status -- Explicitly enable or disable greylisting globally.
                   Possible values: enable, disable.
        """
        form = web.input(_unicode=False)

        domain = str(domain).lower()
        status = form.get('status', 'inherit').lower()

        if status in ['enable', 'disable']:
            enable = (status == 'enable')
            qr = lib_greylist.enable_disable_greylist_setting(account='@' + domain, enable=enable)
        else:
            # Remove setting
            qr = lib_greylist.delete_greylist_setting(account='@' + domain)

        return api_render(qr)


class APIUserSetting:
    @decorators.api_require_domain_access
    def GET(self, mail):
        """Get per-user greylisting setting.

        curl -X GET -i -b cookie.txt https://<server>/api/greylisting/<mail>
        """
        mail = str(mail).lower()
        s = lib_greylist.get_greylist_setting(account=mail)
        return convert_greylist_setting_to_api_json(s)

    @decorators.api_require_domain_access
    def POST(self, mail):
        """Set per-user greylisting setting.

        curl -X POST -i -b cookie.txt -d "status=enable" https://<server>/api/greylisting/<mail>

        Required parameters:

        @status -- Explicitly enable or disable greylisting globally.
                   Possible values: enable, disable.
        """
        form = web.input(_unicode=False)
        status = form.get('status', 'inherit').lower()

        mail = str(mail).lower()

        if status in ['enable', 'disable']:
            enable = (status == 'enable')
            qr = lib_greylist.enable_disable_greylist_setting(account=mail, enable=enable)
        else:
            # Remove setting
            qr = lib_greylist.delete_greylist_setting(account=mail)

        return api_render(qr)


def _get_account_whitelists(account):
    account = str(account).lower()

    if not (iredutils.is_domain(account)
            or iredutils.is_email(account)
            or account == '@.'):
        return False, 'INVALID_ACCOUNT'

    if iredutils.is_domain(account):
        account = '@' + account

    wl = lib_greylist.get_greylist_whitelists(account=account, address_only=True)
    _result = {'whitelists': wl}

    if account == '@.':
        wl_domains = lib_greylist.get_greylist_whitelist_domains()
        _result['whitelist_domains'] = wl_domains

    return True, _result


def _update_account_whitelists(account, form):
    account = str(account).lower()

    if not (iredutils.is_domain(account)
            or iredutils.is_email(account)
            or account == '@.'):
        return False, 'INVALID_ACCOUNT'

    if iredutils.is_domain(account):
        account = '@' + account

    if 'senders' in form:
        # Reset whitelisted senders
        _senders = form.get('senders', '').strip().split(',')

        _senders = [str(i).lower()
                    for i in _senders
                    if iredutils.is_valid_wblist_address(i)]

        _senders = list(set(_senders))

        qr = lib_greylist.reset_greylist_whitelists(account=account,
                                                    whitelists=_senders)
        if not qr[0]:
            return qr
    else:
        # Add new whitelist senders
        _new = []
        if 'addSenders' in form:
            _new = form.get('addSenders', '').strip().split(',')

        # Remove existing ones
        _removed = []
        if 'removeSenders' in form:
            _removed = form.get('removeSenders', '').strip().split(',')

        qr = lib_greylist.update_greylist_whitelists(account=account,
                                                     new=_new,
                                                     removed=_removed)

        if not qr[0]:
            return qr

    return True,


class APIGlobalWhitelists:
    @decorators.api_require_global_admin
    def GET(self):
        """Get globally whitelisted senders for greylisting service.

        curl -X GET -i -b cookie.txt https://<server>/api/greylisting/global/whitelists
        """
        qr = _get_account_whitelists(account='@.')
        return api_render(qr)

    @decorators.api_require_global_admin
    def POST(self):
        """Set global greylisting setting.

        curl -X POST -i -b cookie.txt -d "var=value&var2=value2" https://<server>/api/greylisting/global/whitelists

        Optional parameters:

        @senders - Reset whitelisted senders for global greylisting
                   service to given senders. Multiple addresses must
                   be separated by comma. Conflicts with parameter
                   `addSenders` and `removeSenders`.
        @addSenders - Whitelist new senders for greylisting service
                      globally. Multiple addresses must be separated by
                      comma. Conflicts with parameter `senders`.
        @removeSenders - Remove existing whitelisted senders for
                         greylisting service globally. Multiple
                         addresses must be separated by comma.
                         Conflicts with parameter `senders`.
        """
        form = web.input(_unicode=False)

        qr = _update_account_whitelists(account='@.', form=form)
        if not qr[0]:
            return api_render(qr)

        return api_render(True)


class APIGlobalWhitelist:
    """Handle single whitelist."""
    @decorators.api_require_global_admin
    def PUT(self, ip):
        """
        Whitelist given IP address globally.
        curl -X PUT -i -b cookie.txt https://<server>/api/greylisting/global/whitelist/<ip>
        """
        qr = lib_greylist.update_greylist_whitelists(account='@.', new=[ip], removed=None)
        return api_render(qr)


class APIDomainWhitelists:
    @decorators.api_require_domain_access
    def GET(self, domain):
        """Get whitelisted senders for greylisting service for given domain.

        curl -X GET -i -b cookie.txt https://<server>/api/greylisting/<domain>/whitelists
        """
        qr = _get_account_whitelists(account=domain)
        return api_render(qr)

    @decorators.api_require_domain_access
    def POST(self, domain):
        """Set global greylisting setting.

        curl -X POST -i -b cookie.txt -d "var=value&var2=value2" https://<server>/api/greylisting/<domain>/whitelists

        Optional parameters:

        @senders - Reset whitelisted senders
        @addSenders - Whitelist new senders for greylisting service
        @removeSenders - Remove existing whitelisted senders
        """
        form = web.input(_unicode=False)

        qr = _update_account_whitelists(account=domain, form=form)
        if not qr[0]:
            return api_render(qr)

        return api_render(True)


class APIUserWhitelists:
    @decorators.api_require_domain_access
    def GET(self, mail):
        """Get whitelisted senders for greylisting service for given user.

        curl -X GET -i -b cookie.txt https://<server>/api/greylisting/<mail>/whitelists
        """
        qr = _get_account_whitelists(account=mail)
        return api_render(qr)

    @decorators.api_require_domain_access
    def POST(self, mail):
        """Set global greylisting setting.

        curl -X POST -i -b cookie.txt -d "var=value&var2=value2" https://<server>/api/greylisting/<mail>/whitelists

        Optional parameters:

        @senders - Reset whitelisted senders
        @addSenders - Whitelist new senders for greylisting service
        @removeSenders - Remove existing whitelisted senders
        """
        form = web.input(_unicode=False)

        qr = _update_account_whitelists(account=mail, form=form)
        if not qr[0]:
            return api_render(qr)

        return api_render(True)


def _update_whitelist_spf_domains(form):
    if 'domains' in form:
        # Reset
        _domains = form.get('domains', '').strip().split(',')

        _domains = [str(i).lower()
                    for i in _domains
                    if iredutils.is_domain(i)]

        _domains = list(set(_domains))

        qr = lib_greylist.reset_greylist_whitelist_domains(domains=_domains)
        if not qr[0]:
            return qr
    else:
        # Add new
        _new = []
        if 'addDomains' in form:
            _new = form.get('addDomains', '').strip().split(',')

        # Remove existing ones
        _removed = []
        if 'removeDomains' in form:
            _removed = form.get('removeDomains', '').strip().split(',')

        qr = lib_greylist.update_greylist_whitelist_domains(new=_new, removed=_removed)

        if not qr[0]:
            return qr

    return True,


class APIWhitelistSPFDomain:
    @decorators.api_require_global_admin
    def GET(self):
        """Get whitelisted sender domains (for SPF query) for greylisting service.

        curl -X GET -i -b cookie.txt https://<server>/api/greylisting/whitelist_spf_domains
        """
        domains = lib_greylist.get_greylist_whitelist_domains()
        return api_render((True, {'domains': domains}))

    @decorators.api_require_global_admin
    def POST(self):
        """Manage whitelisted sender domains (for SPF query) for greylisting service.

        curl -X POST -i -b cookie.txt -d "var=value&var2=value2" https://<server>/api/greylisting/whitelist_spf_domains

        Optional parameters:

        @domains - Reset sender domains
        @addDomains - Add new sender domains
        @removeDomains - Remove existing sender domains

        Note: given sender domain names are not used directly while checking
              whitelisting, instead, there's a cron job to query SPF and MX
              DNS records of given sender domains, then whitelist the IP
              addresses/networks listed in DNS records. Multiple domains must
              be separated by comma.

        """
        form = web.input(_unicode=False)
        qr = _update_whitelist_spf_domains(form)
        return api_render(qr)
