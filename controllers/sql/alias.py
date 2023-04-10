# Author: Zhang Huangbin <zhb@iredmail.org>

import web

from libs import iredutils, form_utils
from libs.sqllib import SQLWrap, decorators
from libs.sqllib import alias as sql_lib_alias
from libs.sqllib import admin as sql_lib_admin
from libs.sqllib import domain as sql_lib_domain
from libs.sqllib import general as sql_lib_general
from libs.sqllib import utils as sql_lib_utils

session = web.config.get('_session')


class List:
    @decorators.require_domain_access
    def GET(self, domain, cur_page=1, disabled_only=False):
        domain = str(domain).lower()
        cur_page = int(cur_page) or 1

        form = web.input(_unicode=False)

        all_first_chars = []
        first_char = None
        if 'starts_with' in form:
            first_char = form.get('starts_with')[:1].upper()
            if not iredutils.is_valid_account_first_char(first_char):
                first_char = None

        _wrap = SQLWrap()
        conn = _wrap.conn

        total = sql_lib_alias.num_aliases_under_domain(conn=conn,
                                                       domain=domain,
                                                       disabled_only=disabled_only,
                                                       first_char=first_char)

        records = []
        if total:
            _qr = sql_lib_general.get_first_char_of_all_accounts(domain=domain,
                                                                 account_type='alias',
                                                                 conn=conn)
            if _qr[0]:
                all_first_chars = _qr[1]

            qr = sql_lib_alias.get_basic_alias_profiles(conn=conn,
                                                        domain=domain,
                                                        page=cur_page,
                                                        first_char=first_char,
                                                        disabled_only=disabled_only)
            if qr[0]:
                records = qr[1]

        return web.render(
            'sql/alias/list.html',
            cur_domain=domain,
            cur_page=cur_page,
            total=total,
            aliases=records,
            all_first_chars=all_first_chars,
            first_char=first_char,
            disabled_only=disabled_only,
            msg=form.get('msg', None),
        )

    @decorators.csrf_protected
    @decorators.require_domain_access
    def POST(self, domain):
        form = web.input(_unicode=False, mail=[])
        domain = str(domain).lower()

        accounts = form.get('mail', [])
        action = form.get('action', None)
        msg = form.get('msg', None)

        # Filter aliases not under the same domain.
        accounts = [str(v).lower()
                    for v in accounts
                    if iredutils.is_email(v) and str(v).endswith('@' + domain)]

        _wrap = SQLWrap()
        conn = _wrap.conn

        if action == 'delete':
            result = sql_lib_alias.delete_aliases(conn=conn,
                                                  accounts=accounts)
            msg = 'DELETED'
        elif action == 'disable':
            result = sql_lib_utils.set_account_status(conn=conn,
                                                      accounts=accounts,
                                                      account_type='alias',
                                                      enable_account=False)
            msg = 'DISABLED'
        elif action == 'enable':
            result = sql_lib_utils.set_account_status(conn=conn,
                                                      accounts=accounts,
                                                      account_type='alias',
                                                      enable_account=True)
            msg = 'ENABLED'
        else:
            result = (False, 'INVALID_ACTION')

        if result[0]:
            raise web.seeother('/aliases/{}?msg={}'.format(domain, msg))
        else:
            raise web.seeother('/aliases/{}?msg={}'.format(domain, web.urlquote(result[1])))


class ListDisabled:
    @decorators.require_domain_access
    def GET(self, domain, cur_page=1):
        _list = List()
        return _list.GET(domain=domain, cur_page=cur_page, disabled_only=True)


class Create:
    @decorators.require_domain_access
    def GET(self, domain):
        domain = str(domain).lower()

        form = web.input()
        all_domains = []

        # Get all domains, select the first one.
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

        # Get domain profile.
        qr_profile = sql_lib_domain.simple_profile(domain=domain, conn=conn)
        if qr_profile[0]:
            domain_profile = qr_profile[1]
        else:
            raise web.seeother('/domains?msg=%s' % web.urlquote(qr_profile[1]))

        # Cet total number and allocated quota size of existing users under domain.
        num_aliases_under_domain = sql_lib_alias.num_aliases_under_domain(conn=conn, domain=domain)

        return web.render(
            'sql/alias/create.html',
            cur_domain=domain,
            allDomains=all_domains,
            profile=domain_profile,
            num_existing_aliases=num_aliases_under_domain,
            msg=form.get('msg'),
        )

    @decorators.require_domain_access
    @decorators.csrf_protected
    def POST(self, domain):
        domain = str(domain).lower()
        form = web.input()

        domain_in_form = form_utils.get_domain_name(form)

        if domain != domain_in_form:
            raise web.seeother('/domains?msg=PERMISSION_DENIED')

        listname = form_utils.get_single_value(form, input_name='listname', to_string=True)
        mail = listname + '@' + domain

        result = sql_lib_alias.add_alias_from_form(domain=domain, form=form)

        if result[0]:
            raise web.seeother('/profile/alias/general/%s?msg=CREATED' % mail)
        else:
            raise web.seeother('/create/alias/{}?msg={}'.format(domain, web.urlquote(result[1])))


class Profile:
    @decorators.require_domain_access
    def GET(self, profile_type, mail):
        if profile_type == 'rename':
            raise web.seeother('/profile/alias/general/' + mail)

        form = web.input()
        mail = web.safestr(mail).lower()
        domain = mail.split('@', 1)[-1]

        if not iredutils.is_email(mail):
            raise web.seeother('/domains?msg=INVALID_MAIL')

        qr = sql_lib_alias.get_profile(mail=mail,
                                       with_members=True,
                                       with_moderators=True,
                                       conn=None)
        if qr[0]:
            profile = qr[1]
        else:
            raise web.seeother('/aliases/{}?msg={}'.format(domain, web.urlquote(qr[1])))

        return web.render('sql/alias/profile.html',
                          cur_domain=domain,
                          mail=mail,
                          profile_type=profile_type,
                          profile=profile,
                          msg=form.get('msg'))

    @decorators.csrf_protected
    @decorators.require_domain_access
    def POST(self, profile_type, mail):
        form = web.input()

        result = sql_lib_alias.update(mail=mail,
                                      profile_type=profile_type,
                                      form=form)

        if profile_type == 'rename':
            profile_type = 'general'

        if result[0]:
            raise web.seeother('/profile/alias/{}/{}?msg=UPDATED'.format(profile_type, mail))
        else:
            raise web.seeother('/profile/alias/{}/{}?msg={}'.format(profile_type, mail, web.urlquote(result[1])))
