# Author: Zhang Huangbin <zhb@iredmail.org>

import web
import settings

from libs import form_utils
from libs.iredapd import throttle as iredapd_throttle


if settings.backend == 'ldap':
    from libs.ldaplib import decorators
else:
    from libs.sqllib import decorators


# server-wide throttle setting.
class GlobalThrottle:
    @decorators.require_global_admin
    def GET(self):
        inbound_setting = iredapd_throttle.get_throttle_setting(account='@.', inout_type='inbound')
        outbound_setting = iredapd_throttle.get_throttle_setting(account='@.', inout_type='outbound')

        return web.render('iredapd/throttle_global.html',
                          inbound_setting=inbound_setting,
                          outbound_setting=outbound_setting,
                          msg=web.input().get('msg'))

    @decorators.require_global_admin
    def POST(self):
        form = web.input(_unicode=False)

        t_account = '@.'

        inbound_setting = form_utils.get_throttle_setting(form, account=t_account, inout_type='inbound')
        outbound_setting = form_utils.get_throttle_setting(form, account=t_account, inout_type='outbound')

        iredapd_throttle.add_throttle(account=t_account,
                                      setting=inbound_setting,
                                      inout_type='inbound')

        iredapd_throttle.add_throttle(account=t_account,
                                      setting=outbound_setting,
                                      inout_type='outbound')

        raise web.seeother('/system/throttle?msg=UPDATED')
