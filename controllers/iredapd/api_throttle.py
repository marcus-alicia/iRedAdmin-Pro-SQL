import web
from controllers.utils import api_render
from libs import form_utils
from libs.iredapd import throttle as iredapd_throttle

import settings

if settings.backend == 'ldap':
    from libs.ldaplib import decorators
else:
    from libs.sqllib import decorators


# TODO able to specify quota unit for msg_size and max_quota. e.g. 10MB, 2GB.
# Build form from API POST data and submit the throttle setting
def _add_throttle(form, account, kind):
    form['enable_' + kind + '_throttling'] = 'on'

    if 'period' in form:
        form[kind + '_period'] = form.pop('period')
    else:
        return False, 'MISS_PERIOD'

    _has_rule = False
    for i in ['msg_size', 'max_quota', 'max_msgs']:
        if i in form:
            _has_rule = True

            # radio/checkboxes are toggled
            form[kind + '_' + i] = 'on'

            # value
            form['custom_' + kind + '_' + i] = form.pop(i)

    if not _has_rule:
        return False, 'MISS_THROTTLE_SETTING'

    ts = form_utils.get_throttle_setting(form, account=account, inout_type=kind)
    qr = iredapd_throttle.add_throttle(account=account, setting=ts, inout_type=kind)
    return qr


class APIGlobalThrottle:
    @decorators.require_global_admin
    def GET(self, kind):
        """Get global inbound and outbound throttle settings.

        curl -X GET -i -b cookie.txt https://<server>/api/throttle/global/inbound
        curl -X GET -i -b cookie.txt https://<server>/api/throttle/global/outbound
        """
        ts = iredapd_throttle.get_throttle_setting(account='@.', inout_type=kind)
        return api_render({'_success': True, 'setting': ts})

    @decorators.require_global_admin
    def POST(self, kind):
        """Set global throttle settings.

        curl -X POST -i -b cookie.txt -d "var=value1&var2=value2&..." https://<server>/api/throttle/global/inbound
        curl -X POST -i -b cookie.txt -d "var=value1&var2=value2&..." https://<server>/api/throttle/global/outbound

        Required POST parameters:

        @period - Period of time (in seconds)
        @msg_size - Max size of single email
        @max_msgs - Number of max inbound emails
        @max_quota - Cumulative size of all inbound emails

        Note: at least one of msg_size, max_msgs, max_quota is required.
        """
        form = web.input(_unicode=False)
        qr = _add_throttle(form, account='@.', kind=kind)
        return api_render(qr)


class APIDomainThrottle:
    @decorators.api_require_domain_access
    def GET(self, domain, kind):
        """Set per-domain throttle settings.

        curl -X GET -i -b cookie.txt -d "var=value1&var2=value2&..." https://<server>/api/throttle/<domain>/inbound
        curl -X GET -i -b cookie.txt -d "var=value1&var2=value2&..." https://<server>/api/throttle/<domain>/outbound
        """
        ts = iredapd_throttle.get_throttle_setting(account='@' + domain, inout_type=kind)
        return api_render({'_success': True, 'setting': ts})

    @decorators.api_require_domain_access
    def POST(self, domain, kind):
        """Set per-domain throttle settings.

        curl -X POST -i -b cookie.txt -d "var=value1&var2=value2&..." https://<server>/api/throttle/<domain>/inbound
        curl -X POST -i -b cookie.txt -d "var=value1&var2=value2&..." https://<server>/api/throttle/<domain>/outbound
        """
        form = web.input(_unicode=False)
        qr = _add_throttle(form, account='@' + domain, kind=kind)
        return api_render(qr)


class APIUserThrottle:
    @decorators.api_require_domain_access
    def GET(self, mail, kind):
        """Set per-user throttle settings.

        curl -X GET -i -b cookie.txt -d "var=value1&var2=value2&..." https://<server>/api/throttle/<mail>/inbound
        curl -X GET -i -b cookie.txt -d "var=value1&var2=value2&..." https://<server>/api/throttle/<mail>/outbound
        """
        ts = iredapd_throttle.get_throttle_setting(account=mail, inout_type=kind)
        return api_render({'_success': True, 'setting': ts})

    @decorators.api_require_domain_access
    def POST(self, mail, kind):
        """Set per-user throttle settings.

        curl -X POST -i -b cookie.txt -d "var=value1&var2=value2&..." https://<server>/api/throttle/<mail>/inbound
        curl -X POST -i -b cookie.txt -d "var=value1&var2=value2&..." https://<server>/api/throttle/<mail>/outbound
        """
        form = web.input(_unicode=False)
        qr = _add_throttle(form, account=mail, kind=kind)
        return api_render(qr)
