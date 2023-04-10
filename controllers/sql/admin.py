# Author: Zhang Huangbin <zhb@iredmail.org>

import web
import settings
from libs import iredutils
from libs.l10n import TIMEZONES

from libs.sqllib import SQLWrap, decorators
from libs.sqllib import general as sql_lib_general
from libs.sqllib import user as sql_lib_user
from libs.sqllib import admin as sql_lib_admin
from libs.sqllib import domain as sql_lib_domain
from libs.sqllib import utils as sql_lib_utils

session = web.config.get('_session')


class List:
    @decorators.require_global_admin
    def GET(self, cur_page=1):
        form = web.input()
        cur_page = int(cur_page)

        if cur_page == 0:
            cur_page = 1

        _wrap = SQLWrap()
        conn = _wrap.conn

        result = sql_lib_admin.get_paged_admins(conn=conn,
                                                cur_page=cur_page)

        if result[0]:
            (total, records) = (result[1]['total'], result[1]['records'])

            # Get list of global admins.
            all_global_admins = []
            qr = sql_lib_admin.get_all_global_admins(conn=conn)
            if qr[0]:
                all_global_admins = qr[1]

            return web.render(
                'sql/admin/list.html',
                cur_page=cur_page,
                total=total,
                admins=records,
                allGlobalAdmins=all_global_admins,
                msg=form.get('msg', None),
            )
        else:
            raise web.seeother('/domains?msg=%s' % web.urlquote(result[1]))

    @decorators.require_global_admin
    @decorators.csrf_protected
    def POST(self):
        form = web.input(_unicode=False, mail=[])

        accounts = form.get('mail', [])
        action = form.get('action', None)
        msg = form.get('msg', None)

        _wrap = SQLWrap()
        conn = _wrap.conn

        if action == 'delete':
            result = sql_lib_admin.delete_admins(mails=accounts,
                                                 revoke_admin_privilege_from_user=True,
                                                 conn=conn)
            msg = 'DELETED'
        elif action == 'disable':
            result = sql_lib_utils.set_account_status(conn=conn,
                                                      accounts=accounts,
                                                      account_type='admin',
                                                      enable_account=False)
            msg = 'DISABLED'
        elif action == 'enable':
            result = sql_lib_utils.set_account_status(conn=conn,
                                                      accounts=accounts,
                                                      account_type='admin',
                                                      enable_account=True)
            msg = 'ENABLED'
        else:
            result = (False, 'INVALID_ACTION')

        if result[0]:
            raise web.seeother('/admins?msg=%s' % msg)
        else:
            raise web.seeother('/admins?msg=?' + web.urlquote(result[1]))


class Profile:
    @decorators.require_admin_login
    def GET(self, profile_type, mail):
        mail = str(mail).lower()
        form = web.input()

        if not (session.get('is_global_admin') or session.get('username') == mail):
            # Don't allow to view/update others' profile.
            raise web.seeother('/profile/admin/general/%s?msg=PERMISSION_DENIED' % session.get('username'))

        _wrap = SQLWrap()
        conn = _wrap.conn

        is_global_admin = sql_lib_general.is_global_admin(admin=mail, conn=conn)
        result = sql_lib_admin.get_profile(mail=mail, conn=conn)

        if result[0]:
            profile = result[1]
            qr = sql_lib_general.get_admin_settings(admin=mail, conn=conn)
            if qr[0]:
                admin_settings = qr[1]
            else:
                return qr

            # Get all domains.
            all_domains = []

            qr_all_domains = sql_lib_domain.get_all_domains(conn=conn)
            if qr_all_domains[0]:
                all_domains = qr_all_domains[1]

            # Get managed domains.
            managed_domains = []

            qr = sql_lib_admin.get_managed_domains(conn=conn,
                                                   admin=mail,
                                                   domain_name_only=True,
                                                   listed_only=True)
            if qr[0]:
                managed_domains += qr[1]

            return web.render(
                'sql/admin/profile.html',
                mail=mail,
                profile_type=profile_type,
                is_global_admin=is_global_admin,
                profile=profile,
                admin_settings=admin_settings,
                languagemaps=iredutils.get_language_maps(),
                timezones=TIMEZONES,
                allDomains=all_domains,
                managedDomains=managed_domains,
                min_passwd_length=settings.min_passwd_length,
                max_passwd_length=settings.max_passwd_length,
                store_password_in_plain_text=settings.STORE_PASSWORD_IN_PLAIN_TEXT,
                password_policies=iredutils.get_password_policies(),
                msg=form.get('msg'),
            )
        else:
            # Return to user profile page if admin is a mail user.
            qr = sql_lib_user.simple_profile(conn=conn,
                                             mail=mail,
                                             columns=['username'])

            if qr[0]:
                raise web.seeother('/profile/user/general/' + mail)
            else:
                raise web.seeother('/admins?msg=' + web.urlquote(result[1]))

    @decorators.csrf_protected
    @decorators.require_admin_login
    def POST(self, profile_type, mail):
        mail = str(mail).lower()
        form = web.input(domainName=[])

        if not (session.get('is_global_admin') or session.get('username') == mail):
            # Don't allow to view/update others' profile.
            raise web.seeother('/profile/admin/general/%s?msg=PERMISSION_DENIED' % session.get('username'))

        _wrap = SQLWrap()
        conn = _wrap.conn

        result = sql_lib_admin.update(mail=mail,
                                      profile_type=profile_type,
                                      form=form,
                                      conn=conn)

        if result[0]:
            raise web.seeother('/profile/admin/{}/{}?msg=UPDATED'.format(profile_type, mail))
        else:
            raise web.seeother('/profile/admin/{}/{}?msg={}'.format(profile_type, mail, web.urlquote(result[1])))


class Create:
    @decorators.require_global_admin
    def GET(self):
        form = web.input()
        return web.render('sql/admin/create.html',
                          languagemaps=iredutils.get_language_maps(),
                          default_language=settings.default_language,
                          min_passwd_length=settings.min_passwd_length,
                          max_passwd_length=settings.max_passwd_length,
                          password_policies=iredutils.get_password_policies(),
                          msg=form.get('msg'))

    @decorators.require_global_admin
    @decorators.csrf_protected
    def POST(self):
        form = web.input()
        mail = web.safestr(form.get('mail')).lower()

        qr = sql_lib_admin.add_admin_from_form(form=form, conn=None)

        if qr[0]:
            # Redirect to assign domains.
            raise web.seeother('/profile/admin/general/%s?msg=CREATED' % mail)
        else:
            raise web.seeother('/create/admin?msg=' + web.urlquote(qr[1]))
