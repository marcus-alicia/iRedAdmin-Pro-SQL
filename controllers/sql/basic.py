# Author: Zhang Huangbin <zhb@iredmail.org>

import web
import settings

from controllers.utils import api_render

from libs import __version_sql__ as __version__
from libs import iredutils, sysinfo, form_utils
from libs.logger import logger, log_activity

from libs.sqllib import SQLWrap, auth, decorators
from libs.sqllib import admin as sql_lib_admin
from libs.sqllib import domain as sql_lib_domain
from libs.sqllib import utils as sql_lib_utils
from libs.sqllib import general as sql_lib_general

if settings.iredapd_enabled:
    from libs.iredapd import log as iredapd_log

if settings.fail2ban_enabled:
    from libs.f2b import log as f2b_log

if settings.amavisd_enable_quarantine or settings.amavisd_enable_logging:
    from libs.amavisd import log as lib_amavisd_log


session = web.config.get('_session')


class Login:
    def GET(self):
        if not session.get('logged'):
            form = web.input(_unicode=False)

            if not iredutils.is_allowed_admin_login_ip(client_ip=web.ctx.ip):
                return web.render('error_without_login.html',
                                  error='NOT_ALLOWED_IP')

            # Show login page.
            return web.render('login.html',
                              languagemaps=iredutils.get_language_maps(),
                              msg=form.get('msg'))
        else:
            if session.get('account_is_mail_user'):
                iredutils.self_service_login_redirect(session['username'])
            else:
                if settings.REDIRECT_TO_DOMAIN_LIST_AFTER_LOGIN:
                    raise web.seeother('/domains')
                else:
                    raise web.seeother('/dashboard')

    def POST(self):
        # Get username, password.
        form = web.input(_unicode=False)

        username = form.get('username', '').strip().lower()
        password = str(form.get('password', '').strip())
        domain = username.split('@', 1)[-1]

        # Auth as domain admin
        _wrap = SQLWrap()
        conn = _wrap.conn

        auth_result = auth.auth(conn=conn,
                                username=username,
                                password=password,
                                account_type='admin')

        if auth_result[0]:
            log_activity(msg="Admin login success.", domain=domain, event='login')

            # Save selected language
            selected_language = str(form.get('lang', '')).strip()
            if selected_language != web.ctx.lang and \
               selected_language in iredutils.get_language_maps():
                session['lang'] = selected_language

            account_settings = auth_result[1].get('account_settings', {})
            if (not session.get('is_global_admin')) and 'create_new_domains' in account_settings:
                session['create_new_domains'] = True

            for k in ['disable_viewing_mail_log',
                      'disable_managing_quarantined_mails']:
                if account_settings.get(k) == 'yes':
                    session[k] = True

            if settings.REDIRECT_TO_DOMAIN_LIST_AFTER_LOGIN:
                raise web.seeother('/domains')
            else:
                raise web.seeother('/dashboard?checknew')
        else:
            #
            # User login for self-service
            #
            # Check enabled services.
            qr = sql_lib_domain.get_domain_enabled_services(domain=domain, conn=conn)

            if qr[0]:
                enabled_services = qr[1]
                if 'self-service' not in enabled_services:
                    # domain doesn't allow self-service
                    raise web.seeother('/login?msg=INVALID_CREDENTIALS')
            else:
                raise web.seeother('/login?msg=INVALID_CREDENTIALS')

            user_auth_result = auth.auth(conn=conn,
                                         username=username,
                                         password=password,
                                         account_type='user')

            if user_auth_result[0]:
                log_activity(msg="User login success", event='user_login')

                account_settings = user_auth_result[1].get('account_settings', {})
                if (not session.get('is_global_admin')) and \
                   'create_new_domains' in account_settings:
                    session['create_new_domains'] = True

                iredutils.self_service_login_redirect(session['username'])
            else:
                session['failed_times'] += 1
                logger.warning("Web login failed: client_address={}, username={}".format(web.ctx.ip, username))
                log_activity(msg="Login failed.", admin=username, event='login', loglevel='error')
                raise web.seeother('/login?msg=%s' % web.urlquote(auth_result[1]))


class Logout:
    def GET(self):
        try:
            session.kill()
        except:
            pass

        raise web.seeother('/login')


class Dashboard:
    @decorators.require_admin_login
    def GET(self):
        form = web.input(_unicode=False)
        _check_new_version = ('checknew' in form)

        # Check new version.
        if session.get('is_global_admin') and _check_new_version:
            (_status, _info) = sysinfo.check_new_version()
            session['new_version_available'] = _status
            if _status:
                session['new_version'] = _info
            else:
                session['new_version_check_error'] = _info

        # Get numbers of domains, users, aliases.
        num_existing_domains = 0
        num_existing_users = 0
        num_existing_lists = 0
        num_existing_aliases = 0

        _wrap = SQLWrap()
        conn = _wrap.conn

        try:
            num_existing_domains = sql_lib_admin.num_managed_domains(conn=conn)
            num_existing_users = sql_lib_admin.num_managed_users(conn=conn)
            num_existing_lists = sql_lib_admin.num_managed_lists(conn=conn)
            num_existing_aliases = sql_lib_admin.num_managed_aliases(conn=conn)
        except:
            pass

        #
        # For normal domain admin
        #
        # Get number of max domains/users,aliases. (-1 means no limitation)
        num_max_domains = -1
        num_max_users = -1
        num_max_lists = -1
        num_max_aliases = -1

        admin = session.get('username')
        if (not session.get('is_global_admin')) and session.get('create_new_domains'):
            # Get account settings
            qr = sql_lib_general.get_admin_settings(admin=admin, conn=conn)

            if qr[0]:
                account_settings = qr[1]
                num_max_domains = account_settings.get('create_max_domains', -1)
                num_max_users = account_settings.get('create_max_users', -1)
                num_max_lists = account_settings.get('create_max_lists', -1)
                num_max_aliases = account_settings.get('create_max_aliases', -1)

        # Get numbers of existing messages and quota bytes.
        # Set None as default, so that it's easy to detect them in Jinja2 template.
        total_messages = None
        total_bytes = None
        if session.get('is_global_admin'):
            if settings.SHOW_USED_QUOTA:
                try:
                    qr = sql_lib_admin.sum_all_used_quota(conn=conn)
                    total_messages = qr['messages']
                    total_bytes = qr['bytes']
                except:
                    pass

        # Get number of incoming/outgoing emails in latest 24 hours.
        last_hours = settings.STATISTICS_HOURS
        last_seconds = last_hours * 60 * 60
        num_incoming_mails = 0
        num_outgoing_mails = 0
        num_virus = 0
        num_quarantined = 0
        # iRedAPD
        num_rejected = 0
        num_smtp_outbound_sessions = 0

        top_senders = []
        top_recipients = []

        all_reversed_domain_names = []

        if settings.amavisd_enable_logging or settings.amavisd_enable_quarantine:
            # Get all managed domain names and reversed names.
            _all_domains = []
            result_all_domains = sql_lib_admin.get_managed_domains(conn=conn,
                                                                   admin=session.get('username'),
                                                                   domain_name_only=True)
            if result_all_domains[0]:
                _all_domains += result_all_domains[1]

            all_reversed_domain_names = iredutils.reverse_amavisd_domain_names(_all_domains)

        if settings.amavisd_enable_logging:
            num_incoming_mails = lib_amavisd_log.count_incoming_mails(all_reversed_domain_names, last_seconds)
            num_outgoing_mails = lib_amavisd_log.count_outgoing_mails(all_reversed_domain_names, last_seconds)
            num_virus = lib_amavisd_log.count_virus_mails(all_reversed_domain_names, last_seconds)

            top_senders = lib_amavisd_log.get_top_users(
                reversedDomainNames=all_reversed_domain_names,
                log_type='sent',
                timeLength=last_seconds,
                number=settings.NUM_TOP_SENDERS,
            )

            top_recipients = lib_amavisd_log.get_top_users(
                reversedDomainNames=all_reversed_domain_names,
                log_type='received',
                timeLength=last_seconds,
                number=settings.NUM_TOP_RECIPIENTS,
            )

        # Get records of quarantined mails.
        if settings.amavisd_enable_quarantine:
            num_quarantined = lib_amavisd_log.count_quarantined(all_reversed_domain_names, last_seconds)

        if settings.iredapd_enabled:
            num_rejected = iredapd_log.get_num_rejected(hours=last_hours)
            num_smtp_outbound_sessions = iredapd_log.get_num_smtp_outbound_sessions(
                hours=last_hours,
            )

        num_banned = 0
        if session.get('is_global_admin') and settings.fail2ban_enabled:
            num_banned = f2b_log.num_banned()

        return web.render(
            'dashboard.html',
            version=__version__,
            iredmail_version=sysinfo.get_iredmail_version(),
            hostname=sysinfo.get_hostname(),
            uptime=sysinfo.get_server_uptime(),
            loadavg=sysinfo.get_system_load_average(),
            netif_data=sysinfo.get_nic_info(),
            # number of existing accounts
            num_existing_domains=num_existing_domains,
            num_existing_users=num_existing_users,
            num_existing_lists=num_existing_lists,
            num_existing_aliases=num_existing_aliases,
            # number of account limitation
            num_max_domains=num_max_domains,
            num_max_users=num_max_users,
            num_max_lists=num_max_lists,
            num_max_aliases=num_max_aliases,
            total_messages=total_messages,
            total_bytes=total_bytes,
            # amavisd statistics
            num_incoming_mails=num_incoming_mails,
            num_outgoing_mails=num_outgoing_mails,
            num_virus=num_virus,
            num_quarantined=num_quarantined,
            top_senders=top_senders,
            top_recipients=top_recipients,
            removeQuarantinedInDays=settings.AMAVISD_REMOVE_QUARANTINED_IN_DAYS,
            # iRedAPD
            num_rejected=num_rejected,
            num_smtp_outbound_sessions=num_smtp_outbound_sessions,
            # Fail2ban
            num_banned=num_banned,
        )


class Search:
    @decorators.require_admin_login
    def GET(self):
        form = web.input()
        return web.render('sql/search.html', msg=form.get('msg'))

    @decorators.csrf_protected
    @decorators.require_admin_login
    def POST(self):
        form = web.input(account_type=[], accountStatus=[])
        search_string = form.get('searchString', '').strip()
        if not search_string:
            raise web.seeother('/search?msg=EMPTY_STRING')

        account_type = form.get('account_type', [])
        account_status = form.get('accountStatus', [])

        try:
            _wrap = SQLWrap()
            conn = _wrap.conn

            qr = sql_lib_utils.search(conn=conn,
                                      search_string=search_string,
                                      account_type=account_type,
                                      account_status=account_status)
            if not qr[0]:
                return web.render('sql/search.html',
                                  msg=qr[1],
                                  searchString=search_string)
        except Exception as e:
            return web.render('sql/search.html',
                              msg=repr(e),
                              searchString=search_string)

        # Group account types.
        domains = qr[1].get('domain', [])
        admins = qr[1].get('admin', [])
        users = qr[1].get('user', [])
        mls = qr[1].get('ml', [])
        last_logins = qr[1]['last_logins']
        user_alias_addresses = qr[1]['user_alias_addresses']
        user_forwarding_addresses = qr[1]['user_forwarding_addresses']
        user_assigned_groups = qr[1]['user_assigned_groups']
        aliases = qr[1].get('alias', [])
        all_global_admins = qr[1].get('allGlobalAdmins', [])
        total_results = len(domains) + len(admins) + len(users) + len(aliases) + len(mls)

        if session.get('is_global_admin'):
            days_to_keep_removed_mailbox = settings.DAYS_TO_KEEP_REMOVED_MAILBOX_FOR_GLOBAL_ADMIN
        else:
            days_to_keep_removed_mailbox = settings.DAYS_TO_KEEP_REMOVED_MAILBOX

        return web.render('sql/search.html',
                          searchString=search_string,
                          total_results=total_results,
                          domains=domains,
                          admins=admins,
                          users=users,
                          mls=mls,
                          last_logins=last_logins,
                          user_alias_addresses=user_alias_addresses,
                          user_forwarding_addresses=user_forwarding_addresses,
                          user_assigned_groups=user_assigned_groups,
                          aliases=aliases,
                          allGlobalAdmins=all_global_admins,
                          days_to_keep_removed_mailbox=days_to_keep_removed_mailbox,
                          msg=form.get('msg'))


class OperationsFromSearchPage:
    @decorators.require_admin_login
    def GET(self, *args, **kw):
        raise web.seeother('/search')

    @decorators.csrf_protected
    @decorators.require_admin_login
    def POST(self, account_type):
        account_type = web.safestr(account_type)
        form = web.input(_unicode=False, mail=[])

        # Get action.
        action = form.get('action', None)
        if action not in ['enable', 'disable', 'delete']:
            raise web.seeother('/search?msg=INVALID_ACTION')

        # Get list of accounts which has valid format.
        accounts = [web.safestr(v).lower()
                    for v in form.get('mail', [])
                    if iredutils.is_email(web.safestr(v))]

        # Raise earlier to avoid SQL query.
        if not accounts:
            raise web.seeother('/search?msg=SUCCESS')

        domains = {v.split('@', 1)[-1] for v in accounts}

        _wrap = SQLWrap()
        conn = _wrap.conn

        # Get managed accounts.
        if not session.get('is_global_admin'):
            # Get list of managed domains.
            qr = sql_lib_admin.get_managed_domains(conn=conn,
                                                   admin=session.get('username'),
                                                   domain_name_only=True,
                                                   listed_only=True)
            if qr[0]:
                domains = [d for d in domains if d in qr[1]]
                accounts = [v for v in accounts if v.split('@', 1)[-1] in domains]
            else:
                raise web.seeother('/search?msg=%s' % web.urlquote(qr[1]))

        if not accounts:
            raise web.seeother('/search?msg=SUCCESS')

        if action in ['enable']:
            qr = sql_lib_utils.set_account_status(conn=conn,
                                                  accounts=accounts,
                                                  account_type=account_type,
                                                  enable_account=True)
        elif action in ['disable']:
            qr = sql_lib_utils.set_account_status(conn=conn,
                                                  accounts=accounts,
                                                  account_type=account_type,
                                                  enable_account=False)
        elif action in ['delete']:
            keep_mailbox_days = 0  # keep forever
            if account_type in ['user', 'domain']:
                keep_mailbox_days = form_utils.get_single_value(form=form,
                                                                input_name='keep_mailbox_days',
                                                                default_value=0,
                                                                is_integer=True)
                try:
                    keep_mailbox_days = int(keep_mailbox_days)
                except:
                    if session.get('is_global_admin'):
                        keep_mailbox_days = 0
                    else:
                        _max_days = max(settings.DAYS_TO_KEEP_REMOVED_MAILBOX)
                        if keep_mailbox_days > _max_days:
                            # Get the max days
                            keep_mailbox_days = _max_days

            qr = sql_lib_utils.delete_accounts(accounts=accounts,
                                               account_type=account_type,
                                               keep_mailbox_days=keep_mailbox_days,
                                               conn=conn)
        else:
            raise web.seeother("/search?msg=INVALID_ACTION")

        if qr[0]:
            raise web.seeother('/search?msg=SUCCESS')
        else:
            raise web.seeother('/search?msg=%s' % str(qr[1]))


class APILogin:
    def GET(self):
        return api_render((False, 'INVALID_HTTP_METHOD'))

    def POST(self):
        """Login.

        curl -X POST -c cookie.txt -d "username=<username>&password=<password>" https://<server>/api/login

        Required POST data:

        @username - valid email address of domain admin
        @password - password of username
        """
        if not iredutils.is_allowed_api_client(web.ctx.ip):
            return api_render((False, 'NOT_AUTHORIZED'))

        # Get username, password.
        form = web.input(_unicode=False)

        username = form.get('username', '').strip().lower()
        password = web.safestr(form.get('password', '').strip())
        domain = username.split("@", 1)[-1]

        # Auth as domain admin
        _wrap = SQLWrap()
        conn = _wrap.conn

        auth_result = auth.auth(conn=conn,
                                username=username,
                                password=password,
                                account_type='admin')

        if auth_result[0]:
            log_activity(msg="Admin login success.", domain=domain, event='login')

            return api_render(True)
        else:
            session['failed_times'] += 1
            logger.warning("API login failed: client_address={}, username={}".format(web.ctx.ip, username))
            log_activity(msg="Admin login failed.",
                         admin=username,
                         domain=domain,
                         event='login',
                         loglevel='error')
            return api_render(auth_result)
