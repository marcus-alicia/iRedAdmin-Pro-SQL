# Author: Zhang Huangbin <zhb@iredmail.org>

import web
import settings

from libs import iredutils, form_utils
from libs.l10n import TIMEZONES

from libs.sqllib import SQLWrap, decorators, sqlutils
from libs.sqllib import alias as sql_lib_alias
from libs.sqllib import ml as sql_lib_ml
from libs.sqllib import domain as sql_lib_domain
from libs.sqllib import admin as sql_lib_admin

from libs.amavisd import spampolicy as spampolicylib, wblist as lib_wblist

from libs.panel.domain_ownership import get_pending_domains

session = web.config.get('_session')

if settings.iredapd_enabled:
    from libs.iredapd import throttle as iredapd_throttle
    from libs.iredapd import greylist as iredapd_greylist


class List:
    @decorators.require_admin_login
    def GET(self, cur_page=1, disabled_only=False):
        """List paged mail domains."""
        form = web.input(_unicode=False)
        cur_page = int(cur_page) or 1

        all_domain_profiles = []
        domain_used_quota = {}
        all_first_chars = []

        first_char = None
        if 'starts_with' in form:
            first_char = form.get('starts_with')[:1].upper()
            if not iredutils.is_valid_account_first_char(first_char):
                first_char = None

        _wrap = SQLWrap()
        conn = _wrap.conn

        # Get first characters of all domains - no matter whether it's
        # requested to list all domains or disabled only.
        _qr = sql_lib_domain.get_first_char_of_all_domains(conn=conn)
        if _qr[0]:
            all_first_chars = _qr[1]

        total = sql_lib_admin.num_managed_domains(conn=conn,
                                                  disabled_only=disabled_only,
                                                  first_char=first_char)

        if total:
            qr = sql_lib_domain.get_paged_domains(cur_page=cur_page,
                                                  first_char=first_char,
                                                  disabled_only=disabled_only,
                                                  conn=conn)
            if qr[0]:
                all_domain_profiles = qr[1]

            if settings.SHOW_USED_QUOTA:
                domains = []
                for i in all_domain_profiles:
                    domains.append(str(i.domain))

                domain_used_quota = sql_lib_domain.get_domain_used_quota(conn=conn,
                                                                         domains=domains)

        # Get alias domain names.
        all_domain_names = []
        all_alias_domains = {}
        if all_domain_profiles:
            all_domain_names = [str(d.domain).lower() for d in all_domain_profiles]
            qr = conn.select('alias_domain',
                             vars={'all_domain_names': all_domain_names},
                             what='alias_domain, target_domain',
                             where='target_domain IN $all_domain_names')

            if qr:
                for r in qr:
                    td = str(r.target_domain).lower()
                    ad = str(r.alias_domain).lower()

                    if td in all_alias_domains:
                        all_alias_domains[td].append(ad)
                    else:
                        all_alias_domains[td] = [ad]

        # Query pending domains which didn't passed ownership verification
        pending_domains = []
        if all_domain_names:
            qr = get_pending_domains(domains=all_domain_names, domain_name_only=True)
            if qr[0]:
                pending_domains = qr[1]

        if session.get('is_global_admin'):
            days_to_keep_removed_mailbox = settings.DAYS_TO_KEEP_REMOVED_MAILBOX_FOR_GLOBAL_ADMIN
        else:
            days_to_keep_removed_mailbox = settings.DAYS_TO_KEEP_REMOVED_MAILBOX

        return web.render('sql/domain/list.html',
                          cur_page=cur_page,
                          total=total,
                          all_domain_profiles=all_domain_profiles,
                          all_alias_domains=all_alias_domains,
                          domain_used_quota=domain_used_quota,
                          local_transports=settings.LOCAL_TRANSPORTS,
                          first_char=first_char,
                          all_first_chars=all_first_chars,
                          disabled_only=disabled_only,
                          pending_domains=pending_domains,
                          days_to_keep_removed_mailbox=days_to_keep_removed_mailbox,
                          msg=form.get('msg', None))

    @decorators.require_admin_login
    @decorators.csrf_protected
    def POST(self):
        form = web.input(domainName=[], _unicode=False)
        domains = form.get('domainName', [])
        action = form.get('action')

        if action not in ['delete', 'enable', 'disable']:
            raise web.seeother('/domains?msg=INVALID_ACTION')

        _wrap = SQLWrap()
        conn = _wrap.conn

        if not domains:
            raise web.seeother('/domains?msg=INVALID_DOMAIN_NAME')

        if session.get('is_global_admin') or session.get('create_new_domains'):
            if action == 'delete':
                keep_mailbox_days = form_utils.get_single_value(form=form,
                                                                input_name='keep_mailbox_days',
                                                                default_value=0,
                                                                is_integer=True)

                qr = sql_lib_domain.delete_domains(domains=domains,
                                                   keep_mailbox_days=keep_mailbox_days,
                                                   conn=conn)
                msg = 'DELETED'

            if action in ['enable', 'disable']:
                qr = sql_lib_domain.enable_disable_domains(domains=domains,
                                                           action=action,
                                                           conn=conn)

                # msg: ENABLED, DISABLED
                msg = action.upper() + 'D'

        if qr[0]:
            raise web.seeother('/domains?msg=%s' % msg)
        else:
            raise web.seeother('/domains?msg=' + web.urlquote(qr[1]))


class ListDisabled:
    """List disabled mail domains."""
    @decorators.require_admin_login
    def GET(self, cur_page=1):
        lst = List()
        return lst.GET(cur_page=cur_page, disabled_only=True)


class Profile:
    @decorators.require_domain_access
    def GET(self, profile_type, domain):
        form = web.input()
        domain = web.safestr(domain.split('/', 1)[0])
        profile_type = web.safestr(profile_type)

        _wrap = SQLWrap()
        conn = _wrap.conn

        result = sql_lib_domain.profile(conn=conn, domain=domain)

        if result[0] is not True:
            raise web.seeother('/domains?msg=' + web.urlquote(result[1]))

        domain_profile = result[1]

        alias_domains = []   # Get all alias domains.
        all_alias_accounts = []     # Get all mail alias accounts.
        all_mailing_lists = []

        # profile_type == 'throttle'
        # throttle: iRedAPD
        gl_setting = {}
        gl_whitelists = []
        inbound_throttle_setting = {}
        outbound_throttle_setting = {}

        # Get alias domains.
        qr = sql_lib_domain.get_all_alias_domains(domain=domain,
                                                  name_only=True,
                                                  conn=conn)
        if qr[0]:
            alias_domains = qr[1]

        # Get all mail aliases.
        mails_of_all_alias_accounts = []
        qr = sql_lib_alias.get_basic_alias_profiles(conn=conn,
                                                    domain=domain,
                                                    columns=['name', 'address'])
        if qr[0]:
            all_alias_accounts = qr[1]
            for ali in all_alias_accounts:
                mails_of_all_alias_accounts += [ali.address]

        # Get all mailing lists.
        mails_of_all_mailing_lists = []
        qr = sql_lib_ml.get_basic_ml_profiles(domain=domain,
                                              columns=['address', 'name'],
                                              conn=conn)
        if qr[0]:
            all_mailing_lists = qr[1]
            for i in all_mailing_lists:
                mails_of_all_mailing_lists.append(i['address'])

        # Get per-admin settings used by normal admin to create new domains.
        creation_limits = sql_lib_admin.get_per_admin_domain_creation_limits(admin=session.get('username'), conn=conn)

        # Get sender/recipient throttle data from iRedAPD database.
        if settings.iredapd_enabled:
            _account = '@' + domain

            # Greylisting
            gl_setting = iredapd_greylist.get_greylist_setting(account=_account)
            gl_whitelists = iredapd_greylist.get_greylist_whitelists(account=_account)

            # Throttling
            inbound_throttle_setting = iredapd_throttle.get_throttle_setting(account=_account,
                                                                             inout_type='inbound')
            outbound_throttle_setting = iredapd_throttle.get_throttle_setting(account=_account,
                                                                              inout_type='outbound')

        spampolicy = {}
        global_spam_score = None
        if settings.amavisd_enable_policy_lookup:
            qr = spampolicylib.get_spam_policy(account='@' + domain)
            if not qr[0]:
                raise web.seeother('/domains?msg=%s' % web.urlquote(qr[1]))
            spampolicy = qr[1]

            global_spam_score = spampolicylib.get_global_spam_score()

        # Get per-domain white/blacklists
        whitelists = []
        blacklists = []
        outbound_whitelists = []
        outbound_blacklists = []

        qr = lib_wblist.get_wblist(account='@' + domain)

        if qr[0]:
            whitelists = qr[1]['inbound_whitelists']
            blacklists = qr[1]['inbound_blacklists']
            outbound_whitelists = qr[1]['outbound_whitelists']
            outbound_blacklists = qr[1]['outbound_blacklists']

        # Domain ownership verification
        pending_domains = []
        qr = get_pending_domains(domains=[domain], domain_name_only=True)
        if qr[0]:
            pending_domains = qr[1]

        # Get settings from db.
        _settings = iredutils.get_settings_from_db(params=['min_passwd_length', 'max_passwd_length'])
        global_min_passwd_length = _settings['min_passwd_length']
        global_max_passwd_length = _settings['max_passwd_length']

        return web.render(
            'sql/domain/profile.html',
            cur_domain=domain,
            profile_type=profile_type,
            profile=domain_profile,
            default_mta_transport=settings.default_mta_transport,
            domain_settings=sqlutils.account_settings_string_to_dict(domain_profile['settings']),
            global_min_passwd_length=global_min_passwd_length,
            global_max_passwd_length=global_max_passwd_length,
            alias_domains=alias_domains,
            all_alias_accounts=all_alias_accounts,
            mails_of_all_alias_accounts=mails_of_all_alias_accounts,
            all_mailing_lists=all_mailing_lists,
            mails_of_all_mailing_lists=mails_of_all_mailing_lists,
            timezones=TIMEZONES,
            creation_limits=creation_limits,
            # iRedAPD
            gl_setting=gl_setting,
            gl_whitelists=gl_whitelists,
            inbound_throttle_setting=inbound_throttle_setting,
            outbound_throttle_setting=outbound_throttle_setting,
            # Language
            languagemaps=iredutils.get_language_maps(),
            # Spam policy, wblist
            spampolicy=spampolicy,
            custom_ban_rules=settings.AMAVISD_BAN_RULES,
            global_spam_score=global_spam_score,
            whitelists=whitelists,
            blacklists=blacklists,
            outbound_whitelists=outbound_whitelists,
            outbound_blacklists=outbound_blacklists,
            # domain ownership verification
            pending_domains=pending_domains,
            msg=form.get('msg'),
        )

    @decorators.csrf_protected
    @decorators.require_domain_access
    def POST(self, profile_type, domain):
        domain = str(domain).lower()

        form = web.input(domainAliasName=[],
                         domainAdmin=[],
                         default_mail_list=[],
                         defaultList=[],
                         enabledService=[],
                         disabledMailService=[],
                         disabledDomainProfile=[],
                         disabledUserProfile=[],
                         disabledUserPreference=[],
                         banned_rulenames=[])

        result = sql_lib_domain.update(profile_type=profile_type,
                                       domain=domain,
                                       form=form)

        if result[0]:
            raise web.seeother('/profile/domain/{}/{}?msg=UPDATED'.format(profile_type, domain))
        else:
            raise web.seeother('/profile/domain/{}/{}?msg={}'.format(profile_type, domain, web.urlquote(result[1])))


class Create:
    @decorators.require_permission_create_domain
    def GET(self):
        form = web.input()
        admin = session.get('username')

        # for normal domain admin: check limitations
        creation_limits = sql_lib_admin.get_per_admin_domain_creation_limits(admin=admin)
        if creation_limits['error_code']:
            msg = None
        else:
            msg = form.get('msg')

        return web.render('sql/domain/create.html',
                          preferred_language=settings.default_language,
                          languagemaps=iredutils.get_language_maps(),
                          timezones=TIMEZONES,
                          creation_limits=creation_limits,
                          msg=msg)

    @decorators.require_permission_create_domain
    @decorators.csrf_protected
    def POST(self):
        form = web.input()
        domain = form_utils.get_domain_name(form)

        result = sql_lib_domain.add(form=form)

        if result[0]:
            raise web.seeother('/profile/domain/general/%s?msg=CREATED' % domain)
        else:
            raise web.seeother('/create/domain?msg=%s' % web.urlquote(result[1]))
