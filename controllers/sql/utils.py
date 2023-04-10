import web
from controllers.decorators import require_admin_login
from libs.sqllib import SQLWrap
from libs.sqllib import domain as sql_lib_domain
from libs.sqllib import admin as sql_lib_admin

session = web.config.get('_session')


# Get all domains, select the first one.
class CreateDispatcher:
    @require_admin_login
    def GET(self, account_type):
        _wrap = SQLWrap()
        conn = _wrap.conn

        if session.get('is_global_admin'):
            qr = sql_lib_domain.get_all_domains(conn=conn, name_only=True)
        else:
            qr = sql_lib_admin.get_managed_domains(conn=conn,
                                                   admin=session.get('username'),
                                                   domain_name_only=True)

        if qr[0]:
            all_domains = qr[1]

            # Go to first available domain.
            if all_domains:
                raise web.seeother('/create/{}/{}'.format(account_type, all_domains[0]))
            else:
                raise web.seeother('/domains?msg=NO_DOMAIN_AVAILABLE')
        else:
            raise web.seeother('/domains?msg=' + web.urlquote(qr[1]))
