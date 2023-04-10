# Author: Zhang Huangbin <zhb@iredmail.org>

import web

from libs import iredutils, form_utils

from libs.sqllib import SQLWrap, decorators
from libs.sqllib import ml as sql_lib_ml
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

        total = sql_lib_ml.num_maillists_under_domain(conn=conn,
                                                      domain=domain,
                                                      disabled_only=disabled_only,
                                                      first_char=first_char)

        records = []
        if total:
            _qr = sql_lib_general.get_first_char_of_all_accounts(domain=domain,
                                                                 account_type='ml',
                                                                 conn=conn)
            if _qr[0]:
                all_first_chars = _qr[1]

            qr = sql_lib_ml.get_basic_ml_profiles(conn=conn,
                                                  domain=domain,
                                                  page=cur_page,
                                                  first_char=first_char,
                                                  disabled_only=disabled_only)
            if qr[0]:
                records = qr[1]

        return web.render(
            'sql/ml/list.html',
            cur_domain=domain,
            cur_page=cur_page,
            total=total,
            maillists=records,
            all_first_chars=all_first_chars,
            first_char=first_char,
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
            result = sql_lib_ml.delete_maillists(accounts=accounts,
                                                 keep_archive=True,
                                                 conn=conn)
            msg = 'DELETED'
        elif action == 'delete_without_archiving':
            result = sql_lib_ml.delete_maillists(accounts=accounts,
                                                 keep_archive=False,
                                                 conn=conn)
            msg = 'DELETED'
        elif action == 'disable':
            result = sql_lib_utils.set_account_status(conn=conn,
                                                      accounts=accounts,
                                                      account_type='maillist',
                                                      enable_account=False)
            msg = 'DISABLED'
        elif action == 'enable':
            result = sql_lib_utils.set_account_status(conn=conn,
                                                      accounts=accounts,
                                                      account_type='maillist',
                                                      enable_account=True)
            msg = 'ENABLED'
        else:
            result = (False, 'INVALID_ACTION')

        if result[0]:
            raise web.seeother('/mls/{}?msg={}'.format(domain, msg))
        else:
            raise web.seeother('/mls/{}?msg={}'.format(domain, web.urlquote(result[1])))


class Create:
    @decorators.require_domain_access
    def GET(self, domain):
        domain = str(domain).lower()

        form = web.input()
        all_domains = []

        # Get all domains, select the first one.
        _wrap = SQLWrap()
        conn = _wrap.conn

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

        # Get total number and allocated quota size of existing users under domain.
        num_maillists_under_domain = sql_lib_ml.num_maillists_under_domain(domain=domain, conn=conn)

        # TODO read default creation settings from domain profile.
        # Default creation settings
        default_creation_settings = {'only_subscriber_can_post': 'yes'}

        return web.render(
            'sql/ml/create.html',
            cur_domain=domain,
            allDomains=all_domains,
            profile=domain_profile,
            num_existing_maillists=num_maillists_under_domain,
            default_creation_settings=default_creation_settings,
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

        listname = form_utils.get_single_value(form, input_name='listname', to_string=True, to_lowercase=True)
        mail = listname + '@' + domain

        qr = sql_lib_ml.add_ml_from_web_form(domain=domain, form=form)

        if qr[0]:
            raise web.seeother('/profile/ml/general/%s?msg=CREATED' % mail)
        else:
            raise web.seeother('/create/ml/{}?msg={}'.format(domain, web.urlquote(qr[1])))


class Profile:
    @decorators.require_domain_access
    def GET(self, profile_type, mail):
        form = web.input()
        mail = str(mail).lower()
        domain = mail.split('@', 1)[-1]

        _wrap = SQLWrap()
        conn = _wrap.conn

        # Get mlmmj account profile
        qr = sql_lib_ml.get_profile(mail=mail, conn=conn)
        if qr[0] is not True:
            raise web.seeother('/mls/{}?msg={}'.format(domain, web.urlquote(qr[1])))

        profile = qr[1]

        # Get per-account alias addresses.
        qr = sql_lib_ml.get_alias_addresses(mail=mail, conn=conn)
        if qr[0]:
            alias_addresses = qr[1]
        else:
            raise web.seeother('/mls/{}?msg={}'.format(domain, web.urlquote(qr[1])))

        # Get subscribers
        subscribers = []

        qr = sql_lib_ml.get_subscribers(mail=mail)
        if qr[0]:
            subscribers = qr[1]

        return web.render('sql/ml/profile.html',
                          cur_domain=domain,
                          mail=mail,
                          profile_type=profile_type,
                          profile=profile,
                          alias_addresses=alias_addresses,
                          subscribers=subscribers,
                          msg=form.get('msg'))

    @decorators.csrf_protected
    @decorators.require_domain_access
    def POST(self, profile_type, mail):
        form = web.input(subscriber=[])

        result = sql_lib_ml.update(mail=mail,
                                   profile_type=profile_type,
                                   form=form)

        if result[0]:
            raise web.seeother('/profile/ml/{}/{}?msg=UPDATED'.format(profile_type, mail))
        else:
            raise web.seeother('/profile/ml/{}/{}?msg={}'.format(profile_type, mail, web.urlquote(result[1])))


class AddSubscribers:
    @decorators.csrf_protected
    @decorators.require_domain_access
    def POST(self, mail):
        form = web.input(_unicode=False)
        _require_confirm = 'require_confirm' in form

        qr = sql_lib_ml.add_subscribers(mail=mail, form=form)

        if qr[0]:
            if _require_confirm:
                raise web.seeother('/profile/ml/members/%s?msg=CONFIRM_MAIL_SENT' % mail)
            else:
                raise web.seeother('/profile/ml/members/%s?msg=MEMBERS_ADDED' % mail)
        else:
            raise web.seeother('/profile/ml/members/{}?msg={}'.format(mail, web.urlquote(qr[1])))


class MigrateAliasToML:
    @decorators.csrf_protected
    @decorators.require_domain_access
    def POST(self, mail):
        mail = str(mail).lower()
        domain = mail.split('@', 1)[-1]
        qr = sql_lib_ml.migrate_alias_to_ml(mail=mail)

        if qr[0]:
            raise web.seeother('/profile/ml/general/%s?msg=MIGRATED' % mail)
        else:
            raise web.seeother('/aliases/{}?msg={}'.format(domain, web.urlquote(qr[1])))


# self-service: allow user to manage lists as owner or moderator.
class ManagedMls:
    @decorators.require_preference_access("manageml")
    def GET(self, cur_page=1):
        mail = session['username']
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

        # Get managed mailing lists.
        total = sql_lib_ml.num_maillists_managed_by_user(mail=mail, first_char=first_char, conn=conn)

        rows = []
        if total:
            _qr = sql_lib_ml.get_first_char_of_all_managed_mls(mail=mail, conn=conn)
            if _qr[0]:
                all_first_chars = _qr[1]

            qr = sql_lib_ml.get_basic_profiles_of_managed_mls(
                page=cur_page,
                first_char=first_char,
                conn=conn,
            )
            if qr[0]:
                rows = qr[1]

        return web.render(
            'sql/self-service/ml/list.html',
            cur_page=cur_page,
            total=total,
            maillists=rows,
            all_first_chars=all_first_chars,
            first_char=first_char,
            msg=form.get('msg', None),
        )


class ManagedMlProfile:
    @decorators.require_preference_access("manageml")
    @decorators.require_ml_owner_or_moderator
    def GET(self, profile_type, mail):
        form = web.input()
        mail = str(mail).lower()
        domain = mail.split('@', 1)[-1]

        _wrap = SQLWrap()
        conn = _wrap.conn

        # Get account profile
        qr = sql_lib_ml.get_profile(mail=mail, conn=conn)
        if not qr[0]:
            raise web.seeother('/mls/{}?msg={}'.format(domain, web.urlquote(qr[1])))

        profile = qr[1]

        # Get subscribers
        subscribers = []
        qr = sql_lib_ml.get_subscribers(mail=mail)
        if qr[0]:
            subscribers = qr[1]

        return web.render('sql/self-service/ml/profile.html',
                          mail=mail,
                          profile_type=profile_type,
                          profile=profile,
                          subscribers=subscribers,
                          msg=form.get('msg'))

    @decorators.require_preference_access("manageml")
    @decorators.csrf_protected
    @decorators.require_ml_owner_or_moderator
    def POST(self, profile_type, mail):
        form = web.input(subscriber=[])

        qr = sql_lib_ml.update(mail=mail,
                               profile_type=profile_type,
                               form=form)

        if qr[0]:
            raise web.seeother('/self-service/ml/profile/{}/{}?msg=UPDATED'.format(profile_type, mail))
        else:
            raise web.seeother('/self-service/ml/profile/{}/{}?msg={}'.format(profile_type, mail, web.urlquote(qr[1])))


# self-service
class ManagedMlAddSubscribers:
    @decorators.require_preference_access("manageml")
    @decorators.csrf_protected
    @decorators.require_ml_owner_or_moderator
    def POST(self, mail):
        form = web.input(_unicode=False)

        qr = sql_lib_ml.add_subscribers(mail=mail, form=form)

        if qr[0]:
            raise web.seeother('/self-service/ml/profile/members/%s?msg=MEMBERS_ADDED' % mail)
        else:
            raise web.seeother('/self-service/ml/profile/members/{}?msg={}'.format(mail, web.urlquote(qr[1])))
