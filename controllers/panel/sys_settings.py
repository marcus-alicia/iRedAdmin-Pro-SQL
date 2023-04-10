# Author: Zhang Huangbin <zhb@iredmail.org>

import web
from controllers import decorators
from libs import iredutils, form_utils


class Settings:
    @decorators.require_global_admin
    def GET(self):
        db_settings = iredutils.get_settings_from_db(account='global')
        return web.render('panel/settings.html',
                          db_settings=db_settings)

    @decorators.require_global_admin
    @decorators.csrf_protected
    def POST(self):
        form = web.input()

        # Re-format value of some parameters, then replace the value in `form`.
        # input: textarea
        for k in ['global_admin_ip_list',
                  'admin_login_ip_list',
                  'restful_api_clients']:
            _list = form_utils.get_multi_values(form=form,
                                                input_name=k,
                                                input_is_textarea=True,
                                                is_ip_or_network=True)

            form[k] = _list

        qr = iredutils.store_settings_in_db(kvs=form, flush=True)
        if qr[0]:
            return web.seeother('/system/settings?msg=UPDATED')
        else:
            return web.seeother('/system/settings?msg=' + web.urlquote(qr[1]))
