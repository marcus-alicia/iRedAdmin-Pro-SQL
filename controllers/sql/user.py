# Author: Zhang Huangbin <zhb@iredmail.org>

import web
import settings

from controllers.utils import api_render

from libs import iredutils, form_utils
from libs.l10n import TIMEZONES

from libs.sqllib import SQLWrap, decorators, sqlutils
from libs.sqllib import user as sql_lib_user
from libs.sqllib import alias as sql_lib_alias
from libs.sqllib import ml as sql_lib_ml
from libs.sqllib import admin as sql_lib_admin
from libs.sqllib import domain as sql_lib_domain
from libs.sqllib import utils as sql_lib_utils
from libs.sqllib import general as sql_lib_general
from libs import mlmmj

from libs.amavisd import spampolicy as spampolicylib, wblist as lib_wblist

session = web.config.get('_session')

if settings.iredapd_enabled:
    from libs.iredapd import throttle as iredapd_throttle
    from libs.iredapd import greylist as iredapd_greylist


class List:
    @decorators.require_domain_access
    def GET(self, domain, cur_page=1, disabled_only=False):
        domain = str(domain).lower()
        cur_page = int(cur_page) or 1

        form = web.input(_unicode=False)
        order_name = form.get('order_name')
        order_by_desc = (form.get('order_by', 'asc').lower() == 'desc')

        records = []

        # Real-time used quota.
        used_quotas = {}
        # Last login date
        last_logins = {}

        # Forwardings and per-user alias addresses
        user_forwardings = {}
        user_alias_addresses = {}
        user_assigned_groups = {}

        all_first_chars = []
        first_char = None
        if 'starts_with' in form:
            first_char = form.get('starts_with')[:1].upper()
            if not iredutils.is_valid_account_first_char(first_char):
                first_char = None

        _wrap = SQLWrap()
        conn = _wrap.conn

        total = sql_lib_user.num_users_under_domains(conn=conn,
                                                     domains=[domain],
                                                     disabled_only=disabled_only,
                                                     first_char=first_char)

        if total:
            _qr = sql_lib_general.get_first_char_of_all_accounts(domain=domain,
                                                                 account_type='user',
                                                                 conn=conn)
            if _qr[0]:
                all_first_chars = _qr[1]

            qr = sql_lib_user.get_paged_users(conn=conn,
                                              domain=domain,
                                              cur_page=cur_page,
                                              order_name=order_name,
                                              order_by_desc=order_by_desc,
                                              first_char=first_char,
                                              disabled_only=disabled_only)

            if qr[0]:
                records = qr[1]
            else:
                raise web.seeother('/domains?msg=%s' % web.urlquote(qr[1]))

            # Get list of email addresses
            mails = []
            for r in records:
                mails += [str(r.get('username')).lower()]

            if mails:
                # Get real-time mailbox usage
                if settings.SHOW_USED_QUOTA:
                    try:
                        used_quotas = sql_lib_general.get_account_used_quota(accounts=mails, conn=conn)
                    except Exception:
                        pass

                # Get last login
                last_logins = sql_lib_general.get_account_last_login(accounts=mails, conn=conn)

                # Get user forwardings
                (_status, _result) = sql_lib_user.get_bulk_user_forwardings(conn=conn, mails=mails)
                if _status:
                    user_forwardings = _result
                else:
                    raise web.seeother('/domains?msg=%s' % web.urlquote(_result))

                # Get user alias addresses
                (_status, _result) = sql_lib_user.get_bulk_user_alias_addresses(mails=mails, conn=conn)
                if _status:
                    user_alias_addresses = _result
                else:
                    raise web.seeother('/domains?msg=%s' % web.urlquote(_result))

                # Get assigned groups
                (_status, _result) = sql_lib_user.get_bulk_user_assigned_groups(mails=mails, conn=conn)
                if _status:
                    user_assigned_groups = _result
                else:
                    raise web.seeother('/domains?msg=%s' % web.urlquote(_result))

        if session.get('is_global_admin'):
            days_to_keep_removed_mailbox = settings.DAYS_TO_KEEP_REMOVED_MAILBOX_FOR_GLOBAL_ADMIN
        else:
            days_to_keep_removed_mailbox = settings.DAYS_TO_KEEP_REMOVED_MAILBOX

        return web.render('sql/user/list.html',
                          cur_domain=domain,
                          cur_page=cur_page,
                          total=total,
                          users=records,
                          user_forwardings=user_forwardings,
                          user_alias_addresses=user_alias_addresses,
                          user_assigned_groups=user_assigned_groups,
                          used_quotas=used_quotas,
                          last_logins=last_logins,
                          order_name=order_name,
                          order_by_desc=order_by_desc,
                          all_first_chars=all_first_chars,
                          first_char=first_char,
                          disabled_only=disabled_only,
                          days_to_keep_removed_mailbox=days_to_keep_removed_mailbox,
                          msg=form.get('msg', None))

    @decorators.csrf_protected
    @decorators.require_domain_access
    def POST(self, domain, page=1):
        form = web.input(_unicode=False, mail=[])
        page = int(page)
        if page < 1:
            page = 1

        domain = str(domain).lower()

        # Filter users not under the same domain.
        mails = [str(v).strip().lower() for v in form.get("mail", [])]
        mails = [v for v in mails if iredutils.is_email(v) and v.endswith('@' + domain)]

        action = form.get('action', None)
        msg = form.get('msg', None)

        redirect_to_admin_list = False
        if 'redirect_to_admin_list' in form:
            redirect_to_admin_list = True

        _wrap = SQLWrap()
        conn = _wrap.conn

        if action == 'delete':
            keep_mailbox_days = form_utils.get_single_value(form=form,
                                                            input_name='keep_mailbox_days',
                                                            default_value=0,
                                                            is_integer=True)
            result = sql_lib_user.delete_users(conn=conn,
                                               accounts=mails,
                                               keep_mailbox_days=keep_mailbox_days)
            msg = 'DELETED'
        elif action == 'disable':
            result = sql_lib_utils.set_account_status(conn=conn,
                                                      accounts=mails,
                                                      account_type='user',
                                                      enable_account=False)
            msg = 'DISABLED'
        elif action == 'enable':
            result = sql_lib_utils.set_account_status(conn=conn,
                                                      accounts=mails,
                                                      account_type='user',
                                                      enable_account=True)
            msg = 'ENABLED'
        elif action == 'markasadmin':
            result = sql_lib_user.mark_user_as_admin(conn=conn,
                                                     domain=domain,
                                                     users=mails,
                                                     as_normal_admin=True)
            msg = 'MARKASADMIN'
        elif action == 'unmarkasadmin':
            result = sql_lib_user.mark_user_as_admin(conn=conn,
                                                     domain=domain,
                                                     users=mails,
                                                     as_normal_admin=False)
            msg = 'UNMARKASADMIN'
        elif action == 'markasglobaladmin':
            result = sql_lib_user.mark_user_as_admin(conn=conn,
                                                     domain=domain,
                                                     users=mails,
                                                     as_global_admin=True)
            msg = 'MARKASGLOBALADMIN'
        elif action == 'unmarkasglobaladmin':
            result = sql_lib_user.mark_user_as_admin(conn=conn,
                                                     domain=domain,
                                                     users=mails,
                                                     as_global_admin=False)
            msg = 'UNMARKASGLOBALADMIN'
        else:
            result = (False, 'INVALID_ACTION')

        if result[0]:
            if redirect_to_admin_list:
                raise web.seeother('/admins/%s/page/%d?msg=%s' % (domain, page, msg))
            else:
                raise web.seeother('/users/%s/page/%d?msg=%s' % (domain, page, msg))
        else:
            if redirect_to_admin_list:
                raise web.seeother('/admins/%s/page/%d?msg=%s' % (domain, page, web.urlquote(result[1])))
            else:
                raise web.seeother('/users/%s/page/%d?msg=%s' % (domain, page, web.urlquote(result[1])))


class ListDisabled:
    @decorators.require_domain_access
    def GET(self, domain, cur_page=1):
        _instance = List()
        return _instance.GET(domain=domain, cur_page=cur_page, disabled_only=True)


class Profile:
    # Don't use decorator `@decorators.require_domain_access` here, because if
    # domain admin doesn't manage its own domain, it cannot access its own
    # profile.
    def GET(self, profile_type, mail):
        mail = str(mail).lower()
        domain = mail.split('@', 1)[-1]

        _wrap = SQLWrap()
        conn = _wrap.conn

        # - Allow global admin
        # - normal admin who manages this domain
        # - allow normal admin who doesn't manage this domain, but is updating its own profile
        if sql_lib_general.is_domain_admin(domain=domain, admin=session.get('username'), conn=conn) or \
           (session.get('is_normal_admin') and session.get('username') == mail):
            pass
        else:
            raise web.seeother('/domains?msg=PERMISSION_DENIED')

        if profile_type == 'rename':
            raise web.seeother('/profile/user/general/' + mail)

        form = web.input()
        msg = form.get('msg', '')

        discarded_aliases = form.get('discarded_aliases', '')
        if discarded_aliases:
            discarded_aliases = [i.strip().lower()
                                 for i in discarded_aliases.split(',')]

        # profile_type == 'general'
        used_quota = {}
        last_logins = {}

        # profile_type == 'greylisting'
        # greylisting: iRedAPD
        gl_setting = {}
        gl_whitelists = []

        # profile_type == 'throttle'
        # throttle: iRedAPD
        inbound_throttle_setting = {}
        outbound_throttle_setting = {}

        # profile_type == 'advanced'
        disabled_user_profiles = []  # Per-domain disabled user profiles.

        if mail.startswith('@') and iredutils.is_domain(domain):
            # Catchall account.
            raise web.seeother('/profile/domain/catchall/%s' % domain)

        qr = sql_lib_user.profile(mail=mail, conn=conn)
        if qr[0]:
            user_profile = qr[1]

            if not session.get('is_global_admin'):
                sql_lib_user.redirect_if_user_is_global_admin(conn=conn, mail=mail, user_profile=user_profile)
        else:
            raise web.seeother('/users/{}?msg={}'.format(domain, web.urlquote(qr[1])))
        del qr

        # Get mailbox.allow_nets
        allow_nets = []
        _allow_nets = user_profile.get('allow_nets')
        if _allow_nets:
            allow_nets = _allow_nets.split(',')

        # Get per-user settings
        user_settings = {}
        qr = sql_lib_general.get_user_settings(conn=conn,
                                               mail=mail,
                                               existing_settings=user_profile['settings'])
        if qr[0]:
            user_settings = qr[1]
        del qr

        # Get used quota.
        if settings.SHOW_USED_QUOTA:
            used_quota = sql_lib_general.get_account_used_quota(accounts=[mail], conn=conn)

        # Get last login.
        last_logins = sql_lib_general.get_account_last_login(accounts=[mail], conn=conn)

        # Get basic profile of all mail alias accounts under same domain.
        all_aliases = []
        (_status, _result) = sql_lib_alias.get_basic_alias_profiles(domain=domain, conn=conn)
        if _status:
            all_aliases = _result

        # Get email addresses of mail alias accounts which has current mail
        # user as a member
        assigned_aliases = []
        (_status, _result) = sql_lib_user.get_assigned_aliases(mail=mail, conn=conn)
        if _status:
            assigned_aliases = _result

        # Get per-user alias addresses.
        user_alias_addresses = []
        qr = sql_lib_user.get_user_alias_addresses(mail=mail, conn=conn)
        if qr[0]:
            user_alias_addresses = qr[1]

        # subscribable mailing lists
        all_maillist_addresses = []
        all_subscribed_lists = []

        _qr = sql_lib_ml.get_basic_ml_profiles(domain=domain,
                                               columns=['address', 'name'],
                                               conn=conn)
        if _qr[0]:
            all_maillist_profiles = _qr[1]
            for i in all_maillist_profiles:
                all_maillist_addresses.append(i['address'])
        else:
            return _qr

        # Get subscribed mailing lists
        _qr = mlmmj.get_subscribed_lists(mail=mail, query_all_lists=False)
        if _qr[0]:
            for i in _qr[1]:
                all_subscribed_lists.append(i['mail'])

        # Get per-domain disabled user profiles.
        qr = sql_lib_domain.simple_profile(conn=conn,
                                           domain=domain,
                                           columns=['settings'])

        if qr[0]:
            domain_profile = qr[1]
            domain_settings = sqlutils.account_settings_string_to_dict(domain_profile['settings'])

            disabled_user_profiles = domain_settings.get('disabled_user_profiles', [])

            db_settings = iredutils.get_settings_from_db()
            _min_passwd_length = db_settings['min_passwd_length']
            _max_passwd_length = db_settings['max_passwd_length']

            min_passwd_length = domain_settings.get('min_passwd_length', _min_passwd_length)
            max_passwd_length = domain_settings.get('max_passwd_length', _max_passwd_length)

        # Get sender dependent relayhost
        relayhost = ''
        (_status, _result) = sql_lib_general.get_sender_relayhost(sender=mail, conn=conn)
        if _status:
            relayhost = _result

        if settings.iredapd_enabled:
            # Greylisting
            gl_setting = iredapd_greylist.get_greylist_setting(account=mail)
            gl_whitelists = iredapd_greylist.get_greylist_whitelists(account=mail)

            # Throttling
            inbound_throttle_setting = iredapd_throttle.get_throttle_setting(account=mail, inout_type='inbound')
            outbound_throttle_setting = iredapd_throttle.get_throttle_setting(account=mail, inout_type='outbound')

        # Get managed domains and all domains under control.
        managed_domains = []
        all_domains = []

        if session.get('is_global_admin') or session.get('is_normal_admin') or session.get('allowed_to_grant_admin'):
            qr = sql_lib_admin.get_managed_domains(admin=mail,
                                                   domain_name_only=True,
                                                   listed_only=True,
                                                   conn=conn)
            if qr[0]:
                managed_domains += qr[1]

            if session.get('is_global_admin'):
                qr = sql_lib_domain.get_all_domains(conn=conn,
                                                    columns=['domain', 'description'])
                if qr[0]:
                    all_domains = qr[1]
            else:
                qr = sql_lib_admin.get_managed_domains(conn=conn,
                                                       admin=session.username,
                                                       listed_only=True)
                if qr[0]:
                    all_domains = qr[1]

        # Get spam policy
        spampolicy = {}
        global_spam_score = None
        if settings.amavisd_enable_policy_lookup:
            qr = spampolicylib.get_spam_policy(account=mail)
            if not qr[0]:
                raise web.seeother('/domains?msg=%s' % web.urlquote(qr[1]))
            else:
                spampolicy = qr[1]

            global_spam_score = spampolicylib.get_global_spam_score()

        # Get per-user white/blacklists
        whitelists = []
        blacklists = []
        outbound_whitelists = []
        outbound_blacklists = []

        qr = lib_wblist.get_wblist(account=mail)

        if qr[0]:
            whitelists = qr[1]['inbound_whitelists']
            blacklists = qr[1]['inbound_blacklists']
            outbound_whitelists = qr[1]['outbound_whitelists']
            outbound_blacklists = qr[1]['outbound_blacklists']

        return web.render(
            'sql/user/profile.html',
            cur_domain=domain,
            mail=mail,
            profile_type=profile_type,
            profile=user_profile,
            timezones=TIMEZONES,
            min_passwd_length=min_passwd_length,
            max_passwd_length=max_passwd_length,
            store_password_in_plain_text=settings.STORE_PASSWORD_IN_PLAIN_TEXT,
            password_policies=iredutils.get_password_policies(),
            user_settings=user_settings,
            used_quota=used_quota,
            last_logins=last_logins,
            all_aliases=all_aliases,
            assigned_aliases=assigned_aliases,
            user_alias_addresses=user_alias_addresses,
            user_alias_cross_all_domains=settings.USER_ALIAS_CROSS_ALL_DOMAINS,
            all_maillist_profiles=all_maillist_profiles,
            all_subscribed_lists=all_subscribed_lists,
            disabled_user_profiles=disabled_user_profiles,
            allow_nets=allow_nets,
            managed_domains=managed_domains,
            all_domains=all_domains,
            relayhost=relayhost,
            # iRedAPD
            gl_setting=gl_setting,
            gl_whitelists=gl_whitelists,
            # iRedAPD
            inbound_throttle_setting=inbound_throttle_setting,
            outbound_throttle_setting=outbound_throttle_setting,
            # spam policy, wblist, throttling
            spampolicy=spampolicy,
            custom_ban_rules=settings.AMAVISD_BAN_RULES,
            global_spam_score=global_spam_score,
            whitelists=whitelists,
            blacklists=blacklists,
            outbound_whitelists=outbound_whitelists,
            outbound_blacklists=outbound_blacklists,
            languagemaps=iredutils.get_language_maps(),
            msg=msg,
            discarded_aliases=discarded_aliases,
        )

    # Don't use decorator `@decorators.require_domain_access` here, because if
    # domain admin doesn't manage its own domain, it cannot access its own
    # profile.
    @decorators.csrf_protected
    def POST(self, profile_type, mail):
        form = web.input(
            enabledService=[],
            shadowAddress=[],
            telephoneNumber=[],
            subscribed_list=[],
            memberOfGroup=[],
            oldMemberOfAlias=[],
            memberOfAlias=[],
            domainName=[],      # Managed domains
            banned_rulenames=[],
        )

        mail = str(mail).lower()
        domain = mail.split('@', 1)[-1]

        _wrap = SQLWrap()
        conn = _wrap.conn

        # - Allow global admin
        # - normal admin who manages this domain
        # - allow normal admin who doesn't manage this domain, but is updating its own profile
        if sql_lib_general.is_domain_admin(domain=domain, admin=session.get('username'), conn=conn) or \
           (session.get('is_normal_admin') and session.get('username') == mail):
            pass
        else:
            raise web.seeother('/domains?msg=PERMISSION_DENIED')

        result = sql_lib_user.update(conn=conn,
                                     mail=mail,
                                     profile_type=profile_type,
                                     form=form)

        if profile_type == 'rename':
            profile_type = 'general'

        if result[0]:
            _discarded_aliases = []
            if profile_type == 'aliases':
                # Notify admin the discarded addresses.
                try:
                    _discarded_aliases = result[1]['discarded_aliases']
                except:
                    pass

            if _discarded_aliases:
                raise web.seeother('/profile/user/%s/%s?msg=UPDATED'
                                   '&discarded_aliases=%s' % (profile_type, mail, ','.join(_discarded_aliases)))
            else:
                raise web.seeother('/profile/user/{}/{}?msg=UPDATED'.format(profile_type, mail))
        else:
            raise web.seeother('/profile/user/{}/{}?msg={}'.format(profile_type, mail, web.urlquote(result[1])))


class Create:
    @decorators.require_domain_access
    def GET(self, domain):
        domain = str(domain).lower()

        form = web.input()

        # Get all managed domains.
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
        else:
            raise web.seeother('/domains?msg=' + web.urlquote(qr[1]))

        if not all_domains:
            raise web.seeother('/domains?msg=NO_DOMAIN_AVAILABLE')

        # Get domain profile.
        qr_profile = sql_lib_domain.simple_profile(domain=domain, conn=conn)
        if qr_profile[0]:
            domain_profile = qr_profile[1]
            domain_settings = sqlutils.account_settings_string_to_dict(domain_profile['settings'])
        else:
            raise web.seeother('/domains?msg=%s' % web.urlquote(qr_profile[1]))

        # Cet total number and allocated quota size of existing users under domain.
        num_users_under_domain = sql_lib_general.num_users_under_domain(domain=domain, conn=conn)
        used_quota_size = sql_lib_domain.get_allocated_domain_quota(domains=[domain], conn=conn)

        db_settings = iredutils.get_settings_from_db()
        _min_passwd_length = db_settings['min_passwd_length']
        _max_passwd_length = db_settings['max_passwd_length']

        min_passwd_length = domain_settings.get('min_passwd_length', _min_passwd_length)
        max_passwd_length = domain_settings.get('max_passwd_length', _max_passwd_length)

        return web.render(
            'sql/user/create.html',
            cur_domain=domain,
            all_domains=all_domains,
            profile=domain_profile,
            domain_settings=domain_settings,
            min_passwd_length=min_passwd_length,
            max_passwd_length=max_passwd_length,
            store_password_in_plain_text=settings.STORE_PASSWORD_IN_PLAIN_TEXT,
            num_existing_users=num_users_under_domain,
            usedQuotaSize=used_quota_size,
            languagemaps=iredutils.get_language_maps(),
            password_policies=iredutils.get_password_policies(),
            msg=form.get('msg'),
        )

    @decorators.csrf_protected
    @decorators.require_domain_access
    def POST(self, domain):
        domain = str(domain).lower()
        form = web.input()

        domain_in_form = form_utils.get_domain_name(form)
        if domain != domain_in_form:
            raise web.seeother('/domains?msg=PERMISSION_DENIED')

        # Get domain name, username, cn.
        username = form_utils.get_single_value(form,
                                               input_name='username',
                                               to_string=True)

        qr = sql_lib_user.add_user_from_form(domain=domain, form=form)

        if qr[0]:
            raise web.seeother('/profile/user/general/{}@{}?msg=CREATED'.format(username, domain))
        else:
            raise web.seeother('/create/user/{}?msg={}'.format(domain, web.urlquote(qr[1])))


# Internal domain admins
class Admin:
    @decorators.require_domain_access
    def GET(self, domain, cur_page=1):
        domain = str(domain).lower()
        cur_page = int(cur_page) or 1

        form = web.input(_unicode=False)

        first_char = None
        if 'starts_with' in form:
            first_char = form.get('starts_with')[:1].upper()
            if not iredutils.is_valid_account_first_char(first_char):
                first_char = None

        _wrap = SQLWrap()
        conn = _wrap.conn

        _include_global_admins = settings.SHOW_GLOBAL_ADMINS_IN_PER_DOMAIN_ADMIN_LIST
        qr = sql_lib_admin.get_paged_domain_admins(conn=conn,
                                                   domain=domain,
                                                   include_global_admins=_include_global_admins,
                                                   current_page=cur_page,
                                                   first_char=first_char)

        if not qr[0]:
            raise web.seeother('/domains?msg=%s' % web.urlquote(qr[1]))

        total = qr[1]['total']
        records = qr[1]['records']

        # Get list of email addresses
        mails = []
        for r in records:
            mails += [str(r.get('username'))]

        # Get real-time used quota.
        used_quotas = {}

        if settings.SHOW_USED_QUOTA:
            if mails:
                try:
                    used_quotas = sql_lib_general.get_account_used_quota(accounts=mails, conn=conn)
                except Exception:
                    pass

        # Get user forwardings
        _status, _result = sql_lib_user.get_bulk_user_forwardings(conn=conn, mails=mails)
        if _status:
            user_forwardings = _result
        else:
            raise web.seeother('/domains?msg=%s' % web.urlquote(_result))

        # Get user alias addresses
        (_status, _result) = sql_lib_user.get_bulk_user_alias_addresses(mails=mails, conn=conn)
        if _status:
            user_alias_addresses = _result
        else:
            raise web.seeother('/domains?msg=%s' % web.urlquote(_result))

        # Get assigned groups
        (_status, _result) = sql_lib_user.get_bulk_user_assigned_groups(mails=mails, conn=conn)
        if _status:
            user_assigned_groups = _result
        else:
            raise web.seeother('/domains?msg=%s' % web.urlquote(_result))

        if session.get('is_global_admin'):
            days_to_keep_removed_mailbox = settings.DAYS_TO_KEEP_REMOVED_MAILBOX_FOR_GLOBAL_ADMIN
        else:
            days_to_keep_removed_mailbox = settings.DAYS_TO_KEEP_REMOVED_MAILBOX

        return web.render('sql/user/list.html',
                          cur_domain=domain,
                          cur_page=cur_page,
                          total=total,
                          users=records,
                          user_forwardings=user_forwardings,
                          user_alias_addresses=user_alias_addresses,
                          user_assigned_groups=user_assigned_groups,
                          used_quotas=used_quotas,
                          first_char=first_char,
                          days_to_keep_removed_mailbox=days_to_keep_removed_mailbox,
                          all_are_admins=True,
                          msg=web.input().get('msg', None))


# Preferences allowed to be updated by user
class Preferences:
    @decorators.require_user_login
    def GET(self, profile_type='general'):
        form = web.input()
        mail = session['username']
        domain = mail.split('@', 1)[-1]

        _wrap = SQLWrap()
        conn = _wrap.conn

        qr = sql_lib_user.profile(mail=mail, conn=conn)
        user_profile = qr[1]
        del qr

        # Get per-user settings
        user_settings = {}
        qr = sql_lib_general.get_user_settings(conn=conn,
                                               mail=mail,
                                               existing_settings=user_profile['settings'])
        if qr[0]:
            user_settings = qr[1]
        del qr

        # Get used quota
        used_quota_bytes = 0
        if settings.SHOW_USED_QUOTA:
            used_quota = sql_lib_general.get_account_used_quota(accounts=[mail], conn=conn)

            used_quota_bytes = used_quota.get(mail, {}).get('bytes', 0)

        # Get per-domain disabled user preferences.
        qr = sql_lib_domain.simple_profile(conn=conn,
                                           domain=domain,
                                           columns=['settings'])

        if qr[0]:
            domain_profile = qr[1]
            domain_settings = sqlutils.account_settings_string_to_dict(domain_profile['settings'])

            disabled_user_preferences = domain_settings.get('disabled_user_preferences', [])
            session['disabled_user_preferences'] = disabled_user_preferences

            db_settings = iredutils.get_settings_from_db()
            _min_passwd_length = db_settings['min_passwd_length']
            _max_passwd_length = db_settings['max_passwd_length']

            min_passwd_length = domain_settings.get('min_passwd_length', _min_passwd_length)
            max_passwd_length = domain_settings.get('max_passwd_length', _max_passwd_length)

        password_policies = iredutils.get_password_policies()
        if min_passwd_length > 0:
            password_policies['min_passwd_length'] = min_passwd_length

        if max_passwd_length > 0:
            password_policies['max_passwd_length'] = max_passwd_length

        return web.render(
            'sql/self-service/user/preferences.html',
            cur_domain=domain,
            mail=mail,
            profile_type=profile_type,
            profile=user_profile,
            user_settings=user_settings,
            used_quota_bytes=used_quota_bytes,
            disabled_user_preferences=disabled_user_preferences,
            languagemaps=iredutils.get_language_maps(),
            timezones=TIMEZONES,
            min_passwd_length=min_passwd_length,
            max_passwd_length=max_passwd_length,
            store_password_in_plain_text=settings.STORE_PASSWORD_IN_PLAIN_TEXT,
            password_policies=password_policies,
            msg=form.get('msg'),
        )

    @decorators.csrf_protected
    @decorators.require_user_login
    def POST(self, profile_type='general'):
        mail = session['username']

        form = web.input(telephoneNumber=[])

        _wrap = SQLWrap()
        conn = _wrap.conn

        result = sql_lib_user.update_preferences(conn=conn,
                                                 mail=mail,
                                                 form=form,
                                                 profile_type=profile_type)

        if result[0]:
            raise web.seeother('/preferences?msg=UPDATED')
        else:
            raise web.seeother('/preferences?msg=%s' % web.urlquote(result[1]))


# APIProxyUser proxies requests to RESTful API interface without calling
# the exposed `/api/` url.
class APIProxyUser:
    @decorators.require_domain_access
    def PUT(self, mail):
        form = web.input()
        qr = sql_lib_user.api_update_profile(mail=mail, form=form, conn=None)
        return api_render(qr)


class AllLastLogins:
    @decorators.require_domain_access
    def GET(self, domain):
        domain = domain.lower()
        last_logins = sql_lib_general.get_all_last_logins(domain=domain, conn=None)

        return web.render(
            'sql/user/all_last_logins.html',
            cur_domain=domain,
            last_logins=last_logins,
            # msg=msg,
        )
