# Author: Zhang Huangbin <zhb@iredmail.org>

import web
import settings
from libs import __url_license_terms__
from libs import sysinfo
from controllers import decorators
from libs.panel import LOG_EVENTS, log as loglib

session = web.config.get('_session')

if settings.backend == 'ldap':
    from libs.ldaplib.core import LDAPWrap
    from libs.ldaplib import admin as ldap_lib_admin
    from libs import __version_ldap__ as __version__
elif settings.backend in ['mysql', 'pgsql']:
    from libs import __version_sql__ as __version__
    from libs.sqllib import SQLWrap, admin as sql_lib_admin


class Log:
    @decorators.require_admin_login
    def GET(self):
        form = web.input(_unicode=False)

        # Get queries.
        form_event = web.safestr(form.get('event', 'all'))
        form_domain = web.safestr(form.get('domain', 'all'))
        form_admin = web.safestr(form.get('admin', 'all'))
        form_cur_page = web.safestr(form.get('page', '1'))

        if not form_cur_page.isdigit() or form_cur_page == '0':
            form_cur_page = 1
        else:
            form_cur_page = int(form_cur_page)

        total, entries = loglib.list_logs(event=form_event,
                                          domain=form_domain,
                                          admin=form_admin,
                                          cur_page=form_cur_page)

        # Pre-defined
        all_domain_names = []
        all_admin_emails = []

        if settings.backend == 'ldap':
            _wrap = LDAPWrap()
            conn = _wrap.conn

            # Get all managed domains under control.
            qr = ldap_lib_admin.get_managed_domains(
                admin=session.get('username'),
                domain_name_only=True,
                conn=conn,
            )
            if qr[0]:
                all_domain_names = qr[1]

            # Get all admins.
            if session.get('is_global_admin'):
                result = ldap_lib_admin.list_accounts(attributes=['mail'], conn=conn)
                if result[0] is not False:
                    all_admin_emails = [v[1]['mail'][0] for v in result[1]]
            else:
                all_admin_emails = [form_admin]

        elif settings.backend in ['mysql', 'pgsql']:
            # Get all managed domains under control.
            _wrap = SQLWrap()
            conn = _wrap.conn
            qr = sql_lib_admin.get_managed_domains(
                admin=session.get('username'),
                domain_name_only=True,
                conn=conn,
            )
            if qr[0]:
                all_domain_names = qr[1]

            # Get all admins.
            if session.get('is_global_admin'):
                qr = sql_lib_admin.get_all_admins(columns=['username'], email_only=True, conn=conn)
                if qr[0]:
                    all_admin_emails = qr[1]
            else:
                all_admin_emails = [form_admin]

        all_domain_names.sort()
        all_admin_emails.sort()

        return web.render('panel/log.html',
                          event=form_event,
                          domain=form_domain,
                          admin=form_admin,
                          log_events=LOG_EVENTS,
                          cur_page=form_cur_page,
                          total=total,
                          entries=entries,
                          all_domain_names=all_domain_names,
                          all_admin_emails=all_admin_emails,
                          msg=form.get('msg'))

    @decorators.require_global_admin
    @decorators.csrf_protected
    @decorators.require_admin_login
    def POST(self):
        form = web.input(_unicode=False, id=[])
        action = form.get('action', 'delete')

        delete_all = False
        if action == 'deleteAll':
            delete_all = True

        qr = loglib.delete_logs(form=form, delete_all=delete_all)
        if qr[0]:
            # Keep the log filter.
            form_domain = web.safestr(form.get('domain'))
            form_admin = web.safestr(form.get('admin'))
            form_event = web.safestr(form.get('event'))
            url = 'domain={}&admin={}&event={}'.format(form_domain, form_admin, form_event)

            raise web.seeother('/activities/admins?%s&msg=DELETED' % url)
        else:
            raise web.seeother('/activities/admins?msg=%s' % web.urlquote(qr[1]))


class License:
    @decorators.require_global_admin
    def GET(self):
        qr_info = sysinfo.get_license_info()

        if qr_info[0]:
            latest_ver = qr_info[1].get('latestversion', '1.0')

            has_update = False
            try:
                # Convert version number to major + minor numbers, then
                # convert to integer and compare.
                #
                # Warning: Comparing (float) numbers in string format is not
                # accurate. For example, version "4.10" is "older" than "4.9".
                latest_vers = latest_ver.split(".", 1)
                if len(latest_vers) == 2:
                    latest_major = latest_vers[0]
                    latest_minor = latest_vers[1]
                else:
                    latest_major = latest_ver
                    latest_minor = "0"

                cur_vers = __version__.split(".", 1)
                if len(cur_vers) == 2:
                    cur_major = cur_vers[0]
                    cur_minor = cur_vers[1]
                else:
                    cur_major = __version__
                    cur_minor = "0"

                # Convert to int.
                i_latest_major = int(latest_major)
                i_latest_minor = int(latest_minor)
                i_cur_major = int(cur_major)
                i_cur_minor = int(cur_minor)

                if i_latest_major > i_cur_major:
                    has_update = True

                if (i_latest_major == i_cur_major) and (i_latest_minor > i_cur_minor):
                    has_update = True

                if has_update:
                    session['new_version_available'] = True
                    session['new_version'] = latest_ver
            except:
                pass

            return web.render('panel/license.html',
                              info=qr_info[1],
                              url_license_terms=__url_license_terms__,
                              version=__version__)
        else:
            return web.render('panel/license.html', error=qr_info[1])
