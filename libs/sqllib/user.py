# Author: Zhang Huangbin <zhb@iredmail.org>

import os
import web
import settings

from controllers.utils import api_render

from libs import iredutils, iredpwd, form_utils

from libs.l10n import TIMEZONES
from libs.logger import logger, log_activity

from libs.sqllib import SQLWrap, decorators, sqlutils
from libs.sqllib import general as sql_lib_general
from libs.sqllib import admin as sql_lib_admin
from libs.sqllib import domain as sql_lib_domain
from libs.sqllib import api_utils

from libs import mlmmj

from libs.amavisd import spampolicy as spampolicylib
from libs.amavisd import get_wblist_from_form, wblist as lib_wblist

session = web.config.get('_session', {})

if settings.amavisd_enable_policy_lookup:
    from libs.amavisd.utils import delete_policy_accounts

if settings.iredapd_enabled:
    from libs.iredapd import throttle as iredapd_throttle
    from libs.iredapd import greylist as iredapd_greylist
    from libs.iredapd import utils as iredapd_utils

ENABLED_SERVICES = [
    'enablesmtp', 'enablesmtpsecured',
    'enablepop3', 'enablepop3secured',
    'enableimap', 'enableimapsecured',
    'enablesogo',
    'enablesogowebmail', 'enablesogocalendar', 'enablesogoactivesync',
    'enablemanagesieve', 'enablemanagesievesecured',
    'enablesieve', 'enablesievesecured',
    'enabledeliver',
]


def user_is_global_admin(conn, mail, user_profile=None):
    try:
        if user_profile:
            if user_profile.get('isglobaladmin', 0) == 1:
                return True
        else:
            if not conn:
                _wrap = SQLWrap()
                conn = _wrap.conn

            qr = conn.select('mailbox',
                             vars={'username': mail},
                             what='isglobaladmin',
                             where='username=$username AND isglobaladmin=1',
                             limit=1)
            if qr:
                return True
    except:
        pass

    return False


def redirect_if_user_is_global_admin(conn, mail, user_profile=None, url=None):
    domain = mail.split('@', 1)[-1].lower()

    if user_is_global_admin(conn=conn, mail=mail, user_profile=user_profile):
        if web.ctx.homepath.startswith("/api/"):
            return api_render((False, 'PERMISSION_DENIED_UPDATE_GLOBAL_ADMIN_PROFILE'))
        else:
            if not url:
                url = '/users/%s?msg=PERMISSION_DENIED_UPDATE_GLOBAL_ADMIN_PROFILE' % domain

            raise web.seeother(url)
    else:
        return None


@decorators.require_domain_access
def change_email(mail, new_mail, conn=None):
    if not iredutils.is_email(mail):
        return False, 'INVALID_OLD_EMAIL'

    if not iredutils.is_email(new_mail):
        return False, 'INVALID_NEW_EMAIL'

    old_domain = mail.split('@', 1)[-1]
    new_domain = new_mail.split('@', 1)[-1]

    if old_domain != new_domain:
        return False, 'PERMISSION_DENIED'

    if not conn:
        _wrap = SQLWrap()
        conn = _wrap.conn

    if not sql_lib_general.is_email_exists(mail=mail, conn=conn):
        return False, 'OLD_EMAIL_NOT_EXIST'

    if sql_lib_general.is_email_exists(mail=new_mail, conn=conn):
        return False, 'NEW_EMAIL_ALREADY_EXISTS'

    # Change email address
    try:
        sql_vars = {'mail': mail, 'new_mail': new_mail}

        conn.update('mailbox',
                    vars=sql_vars,
                    username=new_mail,
                    where='username=$mail')

        # Replace old address by the new one in
        #   - `forwardings.address`
        #   - `forwardings.forwarding`
        conn.update('forwardings',
                    vars=sql_vars,
                    address=new_mail,
                    where='address=$mail')

        conn.update('forwardings',
                    vars=sql_vars,
                    forwarding=new_mail,
                    where='forwarding=$mail')

        # Update moderators
        _qr = conn.select("moderators",
                          vars=sql_vars,
                          what="address",
                          where="moderator=$mail")

        if _qr:
            conn.update('moderators',
                        vars=sql_vars,
                        moderator=new_mail,
                        where='moderator=$mail')

            # Update mlmmj.
            _mls = []
            for row in _qr:
                _addr = row["address"].lower()
                _mls.append(_addr)

            if _mls:
                # Exclude mail alias accounts.
                _qr = conn.select("alias",
                                  vars={"mails": _mls},
                                  what="address",
                                  where="address IN $mails")
                if _qr:
                    for row in _qr:
                        _alias_addr = row["address"].lower()
                        _mls.remove(_alias_addr)

            for _addr in _mls:
                # Get existing moderators from mlmmj mailing list profile.
                _qr = mlmmj.get_account_profile(mail=_addr, with_subscribers=False)
                if _qr[0]:
                    _profile = _qr[1]
                    _owners = _profile.get("moderators", [])

                    # Replace old address by the new one.
                    _owners = [i for i in _owners if i != mail]
                    _owners.append(new_mail)

                    # Reset owners.
                    _qr2 = mlmmj.update_account_profile(mail=_addr, data={"moderators": ",".join(_owners)})
                    if not _qr2[0]:
                        logger.error("Failed to reset moderators of mailing list ({}) "
                                     "while changing user email address: "
                                     "{}".format(_addr, repr(_qr2[1])))
                        return False, _qr2[1]

        # Update mailing list owners.
        _qr = conn.select("maillist_owners",
                          vars=sql_vars,
                          what="address",
                          where="owner=$mail")
        if _qr:
            conn.update('maillist_owners',
                        vars=sql_vars,
                        owner=new_mail,
                        where='owner=$mail')

            # Update mlmmj.
            for row in _qr:
                _addr = row["address"].lower()

                # Get existing owners from mlmmj mailing list profile.
                _qr2 = mlmmj.get_account_profile(mail=_addr, with_subscribers=False)
                if _qr2[0]:
                    _profile = _qr2[1]
                    _owners = _profile.get("owner", [])

                    # Replace old address by the new one.
                    _owners = [i for i in _owners if i != mail]
                    _owners.append(new_mail)

                    # Reset owners.
                    _qr3 = mlmmj.update_account_profile(mail=_addr, data={"owner": ",".join(_owners)})
                    if not _qr3[0]:
                        logger.error("Failed to reset owners of mailing list ({}) "
                                     "while changing user email address: "
                                     "{}".format(_addr, repr(_qr3[1])))
                        return False, _qr3[1]

        log_activity(event='update',
                     domain=old_domain,
                     msg="Change user email address: {} -> {}.".format(mail, new_mail))

        return True,
    except Exception as e:
        return False, repr(e)


def delete_users(accounts,
                 keep_mailbox_days=0,
                 conn=None):
    accounts = [v for v in accounts if iredutils.is_email(v)]

    if not accounts:
        return True,

    # Keep mailboxes 'forever', set to 100 years.
    try:
        keep_mailbox_days = abs(int(keep_mailbox_days))
    except:
        if session.get('is_global_admin'):
            keep_mailbox_days = 0
        else:
            _max_days = max(settings.DAYS_TO_KEEP_REMOVED_MAILBOX)
            if keep_mailbox_days > _max_days:
                # Get the max days
                keep_mailbox_days = _max_days

    if keep_mailbox_days == 0:
        sql_keep_days = web.sqlliteral('Null')
    else:
        if settings.backend == 'mysql':
            sql_keep_days = web.sqlliteral('DATE_ADD(CURDATE(), INTERVAL %d DAY)' % keep_mailbox_days)
        elif settings.backend == 'pgsql':
            sql_keep_days = web.sqlliteral("""CURRENT_TIMESTAMP + INTERVAL '%d DAYS'""" % keep_mailbox_days)

    sql_vars = {
        'accounts': accounts,
        'admin': session.get('username'),
        'sql_keep_days': sql_keep_days,
    }

    # Log maildir path of deleted users.
    if settings.backend == 'mysql':
        sql_raw = '''
            INSERT INTO deleted_mailboxes (username, maildir, domain, admin, delete_date)
            SELECT username, \
                   CONCAT(storagebasedirectory, '/', storagenode, '/', maildir) AS maildir, \
                   SUBSTRING_INDEX(username, '@', -1), \
                   $admin, \
                   $sql_keep_days
              FROM mailbox
             WHERE username IN $accounts'''
    elif settings.backend == 'pgsql':
        sql_raw = '''
            INSERT INTO deleted_mailboxes (username, maildir, domain, admin, delete_date)
            SELECT username, \
                   storagebasedirectory || '/' || storagenode || '/' || maildir, \
                   SPLIT_PART(username, '@', 2), \
                   $admin, \
                   $sql_keep_days
              FROM mailbox
             WHERE username IN $accounts'''

    try:
        if not conn:
            _wrap = SQLWrap()
            conn = _wrap.conn

        conn.query(sql_raw, vars=sql_vars)
    except:
        pass

    try:
        for tbl in ['mailbox',
                    'domain_admins',
                    'recipient_bcc_user',
                    'sender_bcc_user',
                    settings.SQL_TBL_USED_QUOTA]:
            conn.delete(tbl,
                        vars=sql_vars,
                        where='username IN $accounts')

        # remove destination bcc addresses.
        for tbl in ['recipient_bcc_user',
                    'sender_bcc_user',
                    'recipient_bcc_domain',
                    'sender_bcc_domain']:
            conn.delete(tbl,
                        vars=sql_vars,
                        where='bcc_address IN $accounts')

        # Remove user from `forwardings`, including:
        #   - per-user mail forwardings
        #   - per-domain catch-all account
        #   - alias membership
        #   - alias moderators
        conn.delete('forwardings',
                    vars=sql_vars,
                    where='address IN $accounts OR forwarding IN $accounts')

        # remove destination moderators.
        conn.delete('moderators',
                    vars=sql_vars,
                    where='moderator IN $accounts')

        # Remove users from subscribed mlmmj mailing lists
        for _mail in accounts:
            _qr = mlmmj.remove_subscriber_from_all_subscribed_lists(subscriber=_mail)
            if not _qr[0]:
                return _qr
    except Exception as e:
        return False, repr(e)

    # Delete records in Amavisd database: users, policy
    if settings.amavisd_enable_policy_lookup:
        delete_policy_accounts(accounts=accounts)

    # Delete data in iRedAPD database
    if settings.iredapd_enabled:
        iredapd_utils.delete_settings_for_removed_users(mails=accounts)

    log_activity(event='delete',
                 domain=accounts[0].split('@', 1)[-1],
                 msg="Delete user: %s." % ', '.join(accounts))

    return True,


@decorators.require_domain_access
def simple_profile(mail, columns=None, conn=None):
    """Return value of sql column `mailbox.settings`.

    @columns -- a list or tuple which contains SQL column names
    """
    if not conn:
        _wrap = SQLWrap()
        conn = _wrap.conn

    sql_what = '*'
    if columns:
        sql_what = ','.join(columns)

    try:
        qr = conn.select('mailbox',
                         vars={'username': mail},
                         what=sql_what,
                         where='username=$username',
                         limit=1)

        if qr:
            return True, list(qr)[0]
        else:
            return False, 'NO_SUCH_ACCOUNT'
    except Exception as e:
        return False, repr(e)


def promote_users_to_be_global_admin(mails, promote=True, conn=None):
    mails = [str(i).lower() for i in mails if iredutils.is_email(i)]
    if not mails:
        return True,

    if not conn:
        _wrap = SQLWrap()
        conn = _wrap.conn

    try:
        sql_vars = {'mails': mails, 'domain': 'ALL'}
        conn.delete('domain_admins',
                    vars=sql_vars,
                    where="username IN $mails AND domain=$domain")

        if promote:
            v = []
            for i in mails:
                v += [{'username': i, 'domain': 'ALL'}]

            conn.multiple_insert('domain_admins', v)

            # Update `vmail.mailbox`
            conn.update('mailbox',
                        vars=sql_vars,
                        isglobaladmin=1,
                        where="username IN $mails")
        else:
            # Update `vmail.mailbox`
            conn.update('mailbox',
                        vars=sql_vars,
                        isglobaladmin=0,
                        where="username IN $mails")

        return True,
    except Exception as e:
        logger.error(e)
        return False, repr(e)


def num_users_under_domains(conn, domains, disabled_only=False, first_char=None):
    # Count separated admin accounts
    num = 0
    if not domains:
        return num

    sql_where = ''
    if disabled_only:
        sql_where = ' AND active=0'

    if first_char:
        sql_where += ' AND username LIKE %s' % web.sqlquote(first_char.lower() + '%')

    sql_vars = {'domains': domains}
    try:
        qr = conn.select('mailbox',
                         vars=sql_vars,
                         what='COUNT(username) AS total',
                         where='domain IN $domains %s' % sql_where)
        if qr:
            num = qr[0].total or 0
    except:
        pass

    return num


@decorators.require_domain_access
def get_paged_users(conn,
                    domain,
                    cur_page=1,
                    admin_only=False,
                    order_name=None,
                    order_by_desc=None,
                    first_char=None,
                    disabled_only=False):
    domain = str(domain).lower()
    cur_page = int(cur_page) or 1

    sql_vars = {'domain': domain}
    sql_where = 'mailbox.domain=%s' % web.sqlquote(domain)

    if admin_only:
        sql_where += ' AND (mailbox.isadmin=1 OR mailbox.isglobaladmin=1)'

    if first_char:
        sql_where += ' AND mailbox.username LIKE %s' % web.sqlquote(first_char.lower() + '%')

    if disabled_only:
        sql_where += ' AND mailbox.active=0'

    try:
        if order_name == 'quota':
            if settings.backend == 'mysql':
                sql_cmd_percentage = '100 * IFNULL(%s.bytes, 0)/(mailbox.quota * 1024 * 1024) AS percentage' % settings.SQL_TBL_USED_QUOTA
            else:
                # ATTENTION:
                #   - 'COALESCE(X, 0) as percentage': set percentage of unlimited mailbox to 0
                #   - 'NULLIF()': set `mailbox.quota` of unlimited mailbox to null,
                #                 this way we can avoid PostgreSQL error: `division by zero`
                sql_cmd_percentage = 'COALESCE((100 * COALESCE(%s.bytes, 0)/(NULLIF(mailbox.quota, 0) * 1024 * 1024)), 0) as percentage' % settings.SQL_TBL_USED_QUOTA

            if order_by_desc:
                _order_by = 'DESC'
            else:
                _order_by = 'ASC'

            qr = conn.query("""
                SELECT
                    mailbox.username, mailbox.name, mailbox.quota,
                    mailbox.employeeid, mailbox.active, mailbox.isadmin,
                    mailbox.isglobaladmin, mailbox.passwordlastchange,
                    %s
                FROM mailbox
                LEFT JOIN %s ON (%s.username = mailbox.username)
                WHERE %s
                ORDER BY percentage %s, mailbox.username ASC
                LIMIT %d
                OFFSET %d
            """ % (sql_cmd_percentage,
                   settings.SQL_TBL_USED_QUOTA, settings.SQL_TBL_USED_QUOTA,
                   sql_where,
                   _order_by,
                   settings.PAGE_SIZE_LIMIT,
                   (cur_page - 1) * settings.PAGE_SIZE_LIMIT))

        elif order_name == 'name':
            sql_order = 'name ASC, username ASC'
            if order_by_desc:
                sql_order = 'name DESC, username ASC'

            qr = conn.select(
                'mailbox',
                vars=sql_vars,
                # Just query what we need to reduce memory use.
                what='username,name,quota,employeeid,active,isadmin,isglobaladmin,passwordlastchange',
                where=sql_where,
                order=sql_order,
                limit=settings.PAGE_SIZE_LIMIT,
                offset=(cur_page - 1) * settings.PAGE_SIZE_LIMIT,
            )

        else:
            qr = conn.select(
                'mailbox',
                vars=sql_vars,
                # Just query what we need to reduce memory use.
                what='username,name,quota,employeeid,active,isadmin,isglobaladmin,passwordlastchange',
                where=sql_where,
                order='username ASC',
                limit=settings.PAGE_SIZE_LIMIT,
                offset=(cur_page - 1) * settings.PAGE_SIZE_LIMIT)

        return True, list(qr)
    except Exception as e:
        return False, repr(e)


def mark_user_as_admin(conn,
                       domain,
                       users,
                       as_normal_admin=None,
                       as_global_admin=None):
    """Mark normal mail user accounts as domain admin.

    @domain -- specified users will be admin of this domain.
    @users -- iterable object which contains list of email addresses.
    @as_normal_admin -- True to enable, False to disable. None for no change.
    @as_global_admin -- True to enable, False to disable. None for no change.
    """
    sql_vars = {'users': users}
    sql_updates = {}

    if as_normal_admin is True:
        sql_updates['isadmin'] = 1
    elif as_normal_admin is False:
        sql_updates['isadmin'] = 0

    if session.get('is_global_admin'):
        if as_global_admin is True:
            sql_updates['isglobaladmin'] = 1
        elif as_global_admin is False:
            sql_updates['isglobaladmin'] = 0

    if not sql_updates:
        return True,

    try:
        # update `mailbox.isadmin`, `mailbox.isglobaladmin`.
        conn.update('mailbox',
                    vars=sql_vars,
                    where='username IN $users',
                    **sql_updates)

        if as_normal_admin is True:
            # Add records in `domain_admins` to identify admin privilege.
            for u in users:
                try:
                    conn.insert('domain_admins',
                                username=u,
                                domain=domain)
                except:
                    pass
        elif as_normal_admin is False:
            # Remove admin privilege.
            try:
                conn.delete('domain_admins',
                            vars={'users': users},
                            where="username IN $users AND domain <> 'ALL'")
            except:
                pass

        if as_global_admin is True:
            promote_users_to_be_global_admin(mails=users, promote=True, conn=conn)
        elif as_global_admin is False:
            promote_users_to_be_global_admin(mails=users, promote=False, conn=conn)

        return True,
    except Exception as e:
        return False, repr(e)


def profile(mail,
            with_aliases=False,
            with_alias_groups=True,
            with_mailing_lists=True,
            with_forwardings=True,
            with_used_quota=True,
            with_last_login=True,
            conn=None):
    """Get full user profile.

    @with_alias -- get per-user alias addresses.
    @with_forwardings -- get mail forwarding addresses
    """
    mail = str(mail).lower()

    try:
        if not conn:
            _wrap = SQLWrap()
            conn = _wrap.conn

        qr = conn.query(
            '''
            SELECT
            mailbox.*,
            sbcc.bcc_address AS sender_bcc_address,
            sbcc.active AS sbcc_active,
            rbcc.bcc_address AS recipient_bcc_address,
            rbcc.active AS rbcc_active
            FROM mailbox
            LEFT JOIN sender_bcc_user AS sbcc ON (mailbox.username = sbcc.username)
            LEFT JOIN recipient_bcc_user AS rbcc ON (mailbox.username = rbcc.username)
            WHERE mailbox.username = $username
            LIMIT 1
            ''',
            vars={'username': mail})

        if qr:
            p = qr[0]
            p['aliases'] = []
            p['mailing_aliases'] = []
            p['mailing_lists'] = []
            p['forwardings'] = []
            p['stored_bytes'] = 0
            p['stored_messages'] = 0

            if with_aliases:
                (_status, _result) = get_user_alias_addresses(mail=mail, conn=conn)
                if _status:
                    p['aliases'] = _result

            if with_alias_groups:
                (_status, _result) = get_assigned_aliases(mail=mail, conn=conn)
                if _status:
                    p['mailing_aliases'] = _result

            if with_mailing_lists:
                (_status, _result) = mlmmj.get_subscribed_lists(mail=mail,
                                                                query_all_lists=False,
                                                                email_only=True)
                if _status:
                    p['mailing_lists'] = _result

            if with_forwardings:
                (_status, _result) = get_user_forwardings(mail=mail, conn=conn)
                if _status:
                    _fwds = _result
                    _fwds.sort()

                    # Remove self if only self exists (no forwarding actually)
                    if _fwds == [mail]:
                        _fwds = []

                    p['forwardings'] = _fwds

            if with_used_quota:
                _used_quota = sql_lib_general.get_account_used_quota(accounts=[mail], conn=conn)
                if mail in _used_quota:
                    p['stored_bytes'] = _used_quota[mail]['bytes']
                    p['stored_messages'] = _used_quota[mail]['messages']

            p['last_login'] = ''
            if with_last_login:
                _last_login = sql_lib_general.get_account_last_login(accounts=[mail], conn=conn)
                if mail in _last_login:
                    _login_epoch_seconds = _last_login[mail]
                    _login_date = iredutils.epoch_seconds_to_gmt(seconds=_login_epoch_seconds)
                    p['last_login'] = _login_date

            return True, p
        else:
            return False, 'NO_SUCH_ACCOUNT'
    except Exception as e:
        return False, repr(e)


def add_user_from_form(domain, form, conn=None):
    # Get domain name, username, cn.
    mail_domain = form_utils.get_domain_name(form)
    mail_username = form.get('username')
    if mail_username:
        mail_username = web.safestr(mail_username).strip().lower()
    else:
        return False, 'INVALID_ACCOUNT'

    mail = mail_username + '@' + mail_domain

    if mail_domain != domain:
        return False, 'PERMISSION_DENIED'

    if not iredutils.is_auth_email(mail):
        return False, 'INVALID_MAIL'

    if not conn:
        _wrap = SQLWrap()
        conn = _wrap.conn

    # Check account existing.
    if sql_lib_general.is_email_exists(mail=mail, conn=conn):
        return False, 'ALREADY_EXISTS'

    # Get domain profile.
    qr = sql_lib_domain.profile(conn=conn, domain=domain)

    if qr[0]:
        domain_profile = qr[1]
        domain_settings = sqlutils.account_settings_string_to_dict(domain_profile['settings'])
    else:
        return qr

    # Check account limit.
    num_exist_accounts = sql_lib_admin.num_managed_users(conn=conn, domains=[domain])

    if domain_profile.mailboxes == -1:
        return False, 'NOT_ALLOWED'
    elif domain_profile.mailboxes > 0:
        if domain_profile.mailboxes <= num_exist_accounts:
            return False, 'EXCEEDED_DOMAIN_ACCOUNT_LIMIT'

    # Check spare quota and number of spare account limit.
    # Get quota from <form>
    quota = str(form.get('mailQuota')).strip()
    qr = sql_lib_domain.assign_given_mailbox_quota(domain=domain, quota=quota)

    if not qr[0]:
        return qr

    quota = qr[1]

    #
    # Get password from <form>.
    #
    pw_hash = form.get('password_hash', '')
    newpw = web.safestr(form.get('newpw', ''))
    confirmpw = web.safestr(form.get('confirmpw', ''))

    if pw_hash:
        if not iredpwd.is_supported_password_scheme(pw_hash):
            return False, 'INVALID_PASSWORD_SCHEME'

        passwd = pw_hash
    else:
        # Get password length limit from domain profile or global setting.
        min_passwd_length = domain_settings.get('min_passwd_length', 0)
        max_passwd_length = domain_settings.get('max_passwd_length', 0)

        qr_pw = iredpwd.verify_new_password(newpw,
                                            confirmpw,
                                            min_passwd_length=min_passwd_length,
                                            max_passwd_length=max_passwd_length)

        if qr_pw[0]:
            pwscheme = None
            if 'store_password_in_plain_text' in form and settings.STORE_PASSWORD_IN_PLAIN_TEXT:
                pwscheme = 'PLAIN'
            passwd = iredpwd.generate_password_hash(qr_pw[1], pwscheme=pwscheme)
        else:
            return qr_pw

    # Get display name from <form>
    cn = form_utils.get_single_value(form, input_name='cn', default_value='')

    # Get preferred language.
    preferred_language = form_utils.get_language(form)
    if preferred_language not in iredutils.get_language_maps():
        preferred_language = ''

    # Assign new user to default mail aliases.
    assigned_aliases = [str(v).lower()
                        for v in domain_settings.get('default_groups', [])
                        if iredutils.is_email(v)]

    # Assign new user to default mailing lists.
    default_mailing_lists = [str(v).lower()
                             for v in domain_settings.get('default_mailing_lists', [])
                             if iredutils.is_email(v)]

    _qr = sql_lib_general.filter_existing_mailing_lists(mails=default_mailing_lists, conn=conn)
    default_mailing_lists = _qr['exist']

    # Get storage base directory.
    _storage_base_directory = settings.storage_base_directory
    splited_sbd = _storage_base_directory.rstrip('/').split('/')
    storage_node = splited_sbd.pop()
    storage_base_directory = '/'.join(splited_sbd)
    maildir = iredutils.generate_maildir_path(mail)

    # Read full maildir path from web form - from RESTful API.
    mailbox_maildir = form.get('maildir', '').lower().rstrip('/')
    if mailbox_maildir and os.path.isabs(mailbox_maildir):
        # Split storageBaseDirectory and storageNode
        _splited = mailbox_maildir.rstrip('/').split('/')
        storage_base_directory = '/' + _splited[0]
        storage_node = _splited[1]
        maildir = '/'.join(_splited[2:])

    record = {
        'domain': domain,
        'username': mail,
        'password': passwd,
        'name': cn,
        'quota': quota,
        'storagebasedirectory': storage_base_directory,
        'storagenode': storage_node,
        'maildir': maildir,
        'language': preferred_language,
        'disclaimer': '',
        'created': iredutils.get_gmttime(),
        'active': 1,
    }

    if settings.SET_PASSWORD_CHANGE_DATE_FOR_NEW_USER:
        record['passwordlastchange'] = iredutils.get_gmttime()

    # Get settings from SQL db.
    db_settings = iredutils.get_settings_from_db()

    # Get mailbox format and folder.
    _mailbox_format = form.get('mailboxFormat', db_settings['mailbox_format']).lower()
    _mailbox_folder = form.get('mailboxFolder', db_settings['mailbox_folder'])
    if iredutils.is_valid_mailbox_format(_mailbox_format):
        record['mailboxformat'] = _mailbox_format

    if iredutils.is_valid_mailbox_folder(_mailbox_folder):
        record['mailboxfolder'] = _mailbox_folder

    # Always store plain password in another attribute.
    if settings.STORE_PLAIN_PASSWORD_IN_ADDITIONAL_ATTR:
        record[settings.STORE_PLAIN_PASSWORD_IN_ADDITIONAL_ATTR] = newpw

    # Set disabled mail services.
    disabled_mail_services = domain_settings.get('disabled_mail_services', [])
    for srv in disabled_mail_services:
        record['enable' + srv] = 0

    # globally disabled mail services
    for srv in settings.ADDITIONAL_DISABLED_USER_SERVICES:
        record['enable' + srv] = 0

    # globally enabled mail services
    for srv in settings.ADDITIONAL_ENABLED_USER_SERVICES:
        record['enable' + srv] = 1

    try:
        # Store new user in SQL db.
        conn.insert('mailbox', **record)

        # Assign new user to default mail aliases.
        if assigned_aliases:
            for ali in assigned_aliases:
                try:
                    conn.insert('forwardings',
                                address=ali,
                                forwarding=mail,
                                domain=ali.split('@', 1)[-1],
                                dest_domain=domain,
                                is_list=1)
                except:
                    pass

        # Assign new user to default mailing lists.
        if default_mailing_lists:
            for ml in default_mailing_lists:
                _qr = mlmmj.add_subscribers(mail=ml,
                                            subscribers=[mail],
                                            subscription='normal',
                                            require_confirm=False)

                if not _qr[0]:
                    return _qr

        # Create an entry in `vmail.forwardings` with `address=forwarding`
        conn.insert('forwardings',
                    address=mail,
                    forwarding=mail,
                    domain=domain,
                    dest_domain=domain,
                    is_forwarding=1,
                    active=1)

        # Create bcc
        for (addr, sql_table) in [(domain_settings.get('default_recipient_bcc'), 'recipient_bcc_user'),
                                  (domain_settings.get('default_sender_bcc'), 'sender_bcc_user')]:
            if iredutils.is_email(addr):
                conn.insert(sql_table,
                            username=mail,
                            bcc_address=addr,
                            domain=domain,
                            created=iredutils.get_gmttime(),
                            active=1)

        log_activity(msg="Create user: %s." % mail,
                     domain=domain,
                     event='create')
        return True,
    except Exception as e:
        return False, repr(e)


def reset_forwardings(mail, forwardings=None, conn=None):
    """Reset per-user mail forwarding addresses.

    If `forwardings` is empty of None, all existing forwardings will be removed.
    """
    domain = mail.split('@', 1)[-1]

    if isinstance(forwardings, (list, tuple, set)):
        _forwardings = {str(i).lower() for i in forwardings if iredutils.is_email(i)}
    else:
        _forwardings = []

    if not conn:
        _wrap = SQLWrap()
        conn = _wrap.conn

    # Remove all forwardings first
    try:
        conn.delete('forwardings',
                    vars={'mail': mail},
                    where='address=$mail')
    except Exception as e:
        return False, repr(e)

    # Return if no need to reset
    if _forwardings:
        # Remove non-existing internal addresses.
        addrs_in_domain = list({v for v in _forwardings if v.endswith('@' + domain)})
        addrs_not_in_domain = list({v for v in _forwardings if not v.endswith('@' + domain)})

        # Verify addresses in same domain
        if addrs_in_domain:
            qr = sql_lib_general.filter_existing_emails(mails=addrs_in_domain, conn=conn)
            addrs_in_domain = qr['exist']

        _forwardings = addrs_in_domain + addrs_not_in_domain
    else:
        _forwardings = [mail]

    if sql_lib_general.is_active_user(mail=mail, conn=conn):
        active = 1
    else:
        active = 0

    try:
        v = []
        for _addr in _forwardings:
            v += [{'address': mail,
                   'forwarding': _addr,
                   'domain': domain,
                   'dest_domain': _addr.split('@', 1)[-1],
                   'is_forwarding': 1,
                   'active': active}]

        conn.multiple_insert('forwardings', values=v)
        return True,
    except Exception as e:
        return False, repr(e)


def __reset_assigned_aliases(mail, groups=None, conn=None):
    """
    Reset assigned mail alias groups. if @groups is empty of None, all
    assigned groups will be removed.
    """
    domain = mail.split('@', 1)[-1]

    _addresses = {str(i).lower()
                  for i in groups
                  if iredutils.is_email(i)}

    if not conn:
        _wrap = SQLWrap()
        conn = _wrap.conn

    # Remove all existing aliases.
    try:
        # NOTE: Use `domain=`, NOT `dest_domain=`.
        conn.delete('forwardings',
                    vars={'mail': mail},
                    where='forwarding=$mail AND is_list=1')
    except Exception as e:
        return False, repr(e)

    # Return if no need to reset
    if not _addresses:
        return True,

    # Get existing mail alias accounts
    qr = sql_lib_general.filter_existing_aliases(mails=_addresses, conn=conn)
    _existings = qr['exist']

    # Remove existing addresses, use non-existing addresses
    if not _existings:
        return True,

    v = []
    for i in _existings:
        v += [{'address': i,
               'forwarding': mail,
               'domain': domain,
               'dest_domain': mail.split('@', 1)[-1],
               'is_list': 1,
               'active': 1}]

    try:
        conn.multiple_insert('forwardings', values=v)
        return True,
    except Exception as e:
        return False, repr(e)


def update(conn, mail, profile_type, form):
    profile_type = web.safestr(profile_type)
    mail = str(mail).lower()
    domain = mail.split('@', 1)[-1]

    # Normal admin is not allowed to update global admin's profile
    # Get user profile.
    if not session.get('is_global_admin'):
        redirect_if_user_is_global_admin(conn=conn, mail=mail)

    # change email address
    if profile_type == 'rename':
        # new email address
        new_mail = web.safestr(form.get('new_mail_username')).strip().lower() + '@' + domain

        qr = change_email(mail=mail, new_mail=new_mail, conn=conn)
        if qr[0]:
            raise web.seeother('/profile/user/general/%s?msg=EMAIL_CHANGED' % new_mail)
        else:
            raise web.seeother('/profile/user/general/{}?msg={}'.format(new_mail, web.urlquote(qr[1])))

    qr = sql_lib_domain.simple_profile(conn=conn,
                                       domain=domain,
                                       columns=['maxquota', 'settings'])
    if not qr[0]:
        return qr

    domain_profile = qr[1]
    del qr

    domain_settings = sqlutils.account_settings_string_to_dict(domain_profile.get('settings', ''))

    disabled_user_profiles = domain_settings.get('disabled_user_profiles', [])
    if not session.get('is_global_admin'):
        if profile_type in disabled_user_profiles:
            return False, 'PERMISSION_DENIED'

    # Pre-defined update key:value pairs
    updates = {'modified': iredutils.get_gmttime()}
    discarded_aliases = []

    if profile_type == 'general':
        managed_domains = []
        if session.get('is_global_admin') or session.get('allowed_to_grant_admin'):
            # Get settings of domain admin and global admin
            if 'domainadmin' in form:
                updates['isadmin'] = 1
                log_activity(msg="User %s is marked as normal domain admin." % mail,
                             domain=domain,
                             admin=session.get('username'),
                             username=mail,
                             event='grant')
            else:
                updates['isadmin'] = 0

            if 'allowed_to_grant_admin' in form:
                sql_lib_general.update_user_settings(conn=conn,
                                                     mail=mail,
                                                     new_settings={'grant_admin': 'yes'})

                log_activity(msg="Grant user {} as domain admin by {}".format(mail, session.get('username')),
                             domain=domain,
                             admin=session.get('username'),
                             username=mail,
                             event='grant')
            else:
                sql_lib_general.update_user_settings(conn=conn,
                                                     mail=mail,
                                                     removed_settings=['grant_admin'])

                if mail == session.get('username'):
                    session['allowed_to_grant_admin'] = False

                if 'old_allowed_to_grant_admin' in form:
                    log_activity(msg="Revoke admin {} by {}".format(mail, session.get('username')),
                                 domain=domain,
                                 admin=session.get('username'),
                                 username=mail,
                                 event='revoke')

        if session.get('is_global_admin'):
            # Mark user as global admin
            if 'domainGlobalAdmin' in form:
                updates['isglobaladmin'] = 1
                managed_domains += ['ALL']

                log_activity(msg="User %s is marked as global admin." % mail,
                             domain=domain,
                             admin=session.get('username'),
                             username=mail,
                             event='grant')
            else:
                updates['isglobaladmin'] = 0

            # Update account settings
            _new_settings = {}
            _removed_settings = []

            for k in ['disable_viewing_mail_log',
                      'disable_managing_quarantined_mails']:
                if k in form:
                    _new_settings[k] = 'yes'
                else:
                    _removed_settings += [k]

            #
            # If marked as normal domain admin, allow to create new domains
            #
            if 'allowed_to_create_domain' in form:
                _new_settings = {'create_new_domains': 'yes'}

                for i in ['create_max_domains',
                          'create_max_quota',
                          'create_max_users',
                          'create_max_aliases']:
                    if i in form:
                        try:
                            v = int(form.get(i, '0'))
                        except:
                            v = 0

                        if v > 0:
                            _new_settings[i] = v
                        else:
                            _removed_settings.append(i)

                if 'create_max_quota' in _new_settings:
                    if 'create_quota_unit' in form:
                        v = form.get('create_quota_unit', 'TB')
                        if v in ['TB', 'GB']:
                            _new_settings['create_quota_unit'] = v
                        else:
                            _removed_settings += ['create_quota_unit']

                for k in ['disable_domain_ownership_verification']:
                    if k in form:
                        _new_settings[k] = 'yes'
                    else:
                        _removed_settings += [k]

            else:
                _removed_settings += ['create_new_domains',
                                      'create_max_domains',
                                      'create_max_quota',
                                      'create_max_users',
                                      'create_max_aliases',
                                      'disable_domain_ownership_verification']

            if _new_settings:
                sql_lib_general.update_user_settings(conn=conn, mail=mail, new_settings=_new_settings)

            if _removed_settings:
                sql_lib_general.update_user_settings(conn=conn, mail=mail, removed_settings=_removed_settings)

        if session.get('is_global_admin') or session.get('allowed_to_grant_admin'):
            # Get managed domains
            managed_domains += form_utils.get_domain_names(form)

            try:
                # Delete records in domain_admins first
                conn.delete('domain_admins',
                            vars={'username': mail},
                            where='username=$username')

                if managed_domains:
                    v = []

                    for d in set(managed_domains):
                        v += [{'username': mail,
                               'domain': d,
                               'created': iredutils.get_gmttime(),
                               'active': 1}]

                    conn.multiple_insert('domain_admins', values=v)
                    del v
            except Exception as e:
                return False, repr(e)

        # Get name
        updates['name'] = form.get('cn', '')

        # Get preferred language: short lang code. e.g. en_US, de_DE.
        preferred_language = form_utils.get_language(form)
        if preferred_language in iredutils.get_language_maps():
            updates['language'] = preferred_language
        else:
            updates['language'] = ''

        tz_name = form_utils.get_timezone(form)
        if tz_name:
            sql_lib_general.update_user_settings(conn=conn,
                                                 mail=mail,
                                                 new_settings={'timezone': tz_name})

            if session['username'] == mail:
                session['timezone'] = TIMEZONES[tz_name]
        else:
            sql_lib_general.update_user_settings(conn=conn,
                                                 mail=mail,
                                                 removed_settings=['timezone'])

        # Update language immediately.
        if session.get('username') == mail and \
           session.get('lang', 'en_US') != preferred_language:
            session['lang'] = preferred_language

        # check account status
        updates['active'] = 0
        if 'accountStatus' in form:
            updates['active'] = 1

        # Update account status in table `forwardings` immediately
        try:
            conn.update('forwardings',
                        vars={'address': mail},
                        where='address=$address OR forwarding=$address',
                        active=updates['active'])
        except:
            pass

        # Get mail quota size.
        mailQuota = str(form.get('mailQuota'))
        if mailQuota.isdigit():
            mailQuota = int(mailQuota)
        else:
            mailQuota = 0

        # Verify mail quota, it cannot exceed domain quota.
        domain_quota = int(domain_profile.get('maxquota', 0))
        max_user_quota = domain_settings.get('max_user_quota', 0)

        if domain_quota == 0:
            # Unlimited domain quota
            if max_user_quota:
                if mailQuota <= max_user_quota:
                    updates['quota'] = mailQuota
                else:
                    updates['quota'] = max_user_quota
            else:
                updates['quota'] = mailQuota
        else:
            # Get domain spare quota
            # Get allocated quota size
            domain_allocated_quota = sql_lib_domain.get_allocated_domain_quota(domains=[domain], conn=conn)

            # Get quota of current user
            qr = simple_profile(conn=conn,
                                mail=mail,
                                columns=['quota'])

            if qr[0]:
                current_user_quota = int(qr[1].quota)
            else:
                return qr

            domain_spare_quota = domain_quota - domain_allocated_quota + current_user_quota

            if domain_spare_quota < 0:
                # Set to 1 MB
                updates['quota'] = 1
            else:
                if mailQuota <= domain_spare_quota:
                    if max_user_quota:
                        if mailQuota <= max_user_quota:
                            updates['quota'] = mailQuota
                        else:
                            updates['quota'] = max_user_quota
                    else:
                        updates['quota'] = mailQuota
                else:
                    if max_user_quota:
                        if domain_spare_quota <= max_user_quota:
                            updates['quota'] = domain_spare_quota
                        else:
                            updates['quota'] = max_user_quota
                    else:
                        updates['quota'] = domain_spare_quota

        # Get employee id.
        updates['employeeid'] = form.get('employeeNumber', '')

        ######################################
        # Member of subscriable mailing lists
        #
        # Get currently subscribed lists.
        _subscribed_lists = []
        _qr = mlmmj.get_subscribed_lists(mail=mail, query_all_lists=False, email_only=True)
        if _qr[0]:
            _subscribed_lists = _qr[1]

        _form_subscribed_lists = [str(i).lower()
                                  for i in form.get('subscribed_list', [])
                                  if i.endswith('@' + domain) and iredutils.is_email(i)]

        _unsubscribe_lists = [i for i in _subscribed_lists if i not in _form_subscribed_lists]
        _new_subscribed_lists = [i for i in _form_subscribed_lists if i not in _subscribed_lists]

        for _list in _unsubscribe_lists:
            # Unsubscribe user from multiple lists
            _qr = mlmmj.remove_subscribers(mail=_list, subscribers=[mail])
            if not _qr[0]:
                return _qr

        if _new_subscribed_lists:
            # Subscribe to multiple lists
            _qr = mlmmj.subscribe_to_lists(subscriber=mail, lists=_new_subscribed_lists)
            if not _qr[0]:
                return _qr

        # Get list of assigned alias accounts.
        _old_assigned_aliases = []
        _qr = get_assigned_aliases(mail=mail, conn=conn)
        if _qr[0]:
            _old_assigned_aliases = _qr[1]

        # Get list of assigned alias from web form.
        _form_new_aliases = [str(i).lower()
                             for i in form.get('memberOfGroup', [])
                             if iredutils.is_email(i)]

        # get aliases in same domain.
        _assigned_internal_aliases = [i for i in _form_new_aliases if i.endswith('@' + domain)]
        _assigned_external_aliases = [i for i in _form_new_aliases if not i.endswith('@' + domain)]

        # Keep old external aliases.
        # WARNING: do NOT add any new external aliases, otherwise normal domain
        #          admin can submit new external aliases.
        _kept_external_aliases = [i for i in _old_assigned_aliases
                                  if not i.endswith('@' + domain) and i in _assigned_external_aliases]

        _assigned_aliases = _assigned_internal_aliases + _kept_external_aliases

        _qr = __reset_assigned_aliases(mail=mail, groups=_assigned_aliases, conn=conn)
        if not _qr[0]:
            return _qr

    elif profile_type == 'forwarding':
        fwd_addresses = form.get('mailForwardingAddresses', '').splitlines()
        fwd_addresses = list({str(v).lower() for v in fwd_addresses if iredutils.is_email(v)})
        if 'savecopy' in form:
            fwd_addresses += [mail]

        qr = reset_forwardings(mail=mail, forwardings=fwd_addresses, conn=conn)
        if not qr[0]:
            return qr

    elif profile_type == 'bcc':
        # Get bcc status
        rbcc_active = 0
        sbcc_active = 0

        if 'recipientbcc' in form:
            rbcc_active = 1
        if 'senderbcc' in form:
            sbcc_active = 1

        # Get sender/recipient bcc.
        _sbcc = form_utils.get_single_value(form=form,
                                            input_name='senderBccAddress',
                                            is_email=True,
                                            to_lowercase=True)

        _rbcc = form_utils.get_single_value(form=form,
                                            input_name='recipientBccAddress',
                                            is_email=True,
                                            to_lowercase=True)

        # BCC must handle alias domains.
        bcc_alias_domains = [domain]

        # Get all alias domains.
        _qr = sql_lib_domain.get_all_alias_domains(domain=domain,
                                                   name_only=True,
                                                   conn=conn)
        if _qr[0]:
            bcc_alias_domains += _qr[1]

        bcc_alias_users = list({mail.split('@', 1)[0] + '@' + d for d in bcc_alias_domains})
        del bcc_alias_domains

        try:
            # Delete bcc records first.
            for u in bcc_alias_users:
                conn.delete('sender_bcc_user',
                            vars={'username': u},
                            where='username=$username')

                conn.delete('recipient_bcc_user',
                            vars={'username': u},
                            where='username=$username')

            # Check local domain and verify existence.
            if iredutils.is_email(_sbcc):
                _sbcc_domain = _sbcc.split("@", 1)[-1]

                if sql_lib_general.is_domain_exists(domain=_sbcc_domain, conn=conn):
                    if not sql_lib_general.is_email_exists(mail=_sbcc, conn=conn):
                        _sbcc = None

            if iredutils.is_email(_rbcc):
                _rbcc_domain = _rbcc.split("@", 1)[-1]

                # Check local domain.
                if sql_lib_general.is_domain_exists(domain=_rbcc_domain, conn=conn):
                    if not sql_lib_general.is_email_exists(mail=_rbcc, conn=conn):
                        _rbcc = None

            # Insert new records.
            if _sbcc:
                for u in bcc_alias_users:
                    conn.insert('sender_bcc_user',
                                username=u,
                                bcc_address=_sbcc,
                                domain=u.split('@', 1)[-1],
                                created=iredutils.get_gmttime(),
                                modified=iredutils.get_gmttime(),
                                active=sbcc_active)

            if _rbcc:
                for u in bcc_alias_users:
                    conn.insert('recipient_bcc_user',
                                username=u,
                                bcc_address=_rbcc,
                                domain=u.split('@', 1)[-1],
                                created=iredutils.get_gmttime(),
                                modified=iredutils.get_gmttime(),
                                active=rbcc_active)

        except Exception as e:
            return False, repr(e)

    elif profile_type == 'relay':
        # Get transport.
        transport = str(form.get('mtaTransport', ''))
        updates['transport'] = transport

        # Get sender dependent relayhost
        relayhost = str(form.get('relayhost', ''))

        # Update relayhost
        _qr = sql_lib_general.update_sender_relayhost(account=mail,
                                                      relayhost=relayhost,
                                                      conn=conn)
        if not _qr[0]:
            return _qr

    elif profile_type == 'aliases':
        if session.get('is_global_admin') or 'aliases' not in disabled_user_profiles:
            user_alias_addresses = form_utils.get_multi_values(form,
                                                               input_name='user_alias_addresses',
                                                               default_value=[],
                                                               input_is_textarea=True,
                                                               is_email=True,
                                                               to_lowercase=True)

            # Remove primary address first.
            if mail in user_alias_addresses:
                user_alias_addresses.remove(mail)

            # Remove all existing per-user aliases first.
            conn.delete('forwardings',
                        vars={'mail': mail},
                        where='forwarding=$mail AND is_alias=1')

            if not settings.USER_ALIAS_CROSS_ALL_DOMAINS:
                # Remove emails not under same domain
                user_alias_addresses = [v for v in user_alias_addresses if v.endswith('@' + domain)]
            else:
                # Remove non-local mail domains
                # Get all local mail domains
                ua_domains = set()
                for addr in user_alias_addresses:
                    ua_domains.add(addr.split('@', 1)[-1])

                # Get exist/nonexist mail domains
                qr = sql_lib_general.filter_existing_domains(conn=conn, domains=ua_domains)
                exist_domains = qr['exist']

                # Remove email addresses in non-local mail domains
                user_alias_addresses = [v for v in user_alias_addresses
                                        if v.split('@', 1)[-1] in exist_domains]

            # Verify existence
            qr = sql_lib_general.filter_existing_emails(conn=conn, mails=user_alias_addresses)
            discarded_aliases = qr['exist']
            nonexist_user_alias_addresses = qr['nonexist']

            # Add all available per-user alias addresses.
            v = []
            for addr in nonexist_user_alias_addresses:
                v += [{'address': addr,
                       'forwarding': mail,
                       'domain': domain,
                       'dest_domain': mail.split('@', 1)[-1],
                       'is_alias': 1,
                       'active': 1}]

            if v:
                conn.multiple_insert('forwardings', values=v)

    elif profile_type == 'throttle':
        if settings.iredapd_enabled:
            t_account = mail

            inbound_setting = form_utils.get_throttle_setting(form, account=t_account, inout_type='inbound')
            outbound_setting = form_utils.get_throttle_setting(form, account=t_account, inout_type='outbound')

            iredapd_throttle.add_throttle(account=t_account,
                                          setting=inbound_setting,
                                          inout_type='inbound')

            iredapd_throttle.add_throttle(account=t_account,
                                          setting=outbound_setting,
                                          inout_type='outbound')

    elif profile_type == 'wblist':
        if session.get('is_global_admin') or 'wblist' not in disabled_user_profiles:
            if settings.amavisd_enable_policy_lookup:
                wl_senders = get_wblist_from_form(form, 'wl_sender')
                bl_senders = get_wblist_from_form(form, 'bl_sender')
                wl_rcpts = get_wblist_from_form(form, 'wl_rcpt')
                bl_rcpts = get_wblist_from_form(form, 'bl_rcpt')

                qr = lib_wblist.add_wblist(account=mail,
                                           wl_senders=wl_senders,
                                           bl_senders=bl_senders,
                                           wl_rcpts=wl_rcpts,
                                           bl_rcpts=bl_rcpts,
                                           flush_before_import=True)
                return qr

    elif profile_type == 'spampolicy':
        qr = spampolicylib.update_spam_policy(account=mail, form=form)
        return qr

    elif profile_type == 'password':
        newpw = web.safestr(form.get('newpw', ''))
        confirmpw = web.safestr(form.get('confirmpw', ''))

        # Get password length limit from domain profile or global setting.
        min_passwd_length = domain_settings.get('min_passwd_length', 0)
        max_passwd_length = domain_settings.get('max_passwd_length', 0)

        # Verify new passwords.
        qr = iredpwd.verify_new_password(newpw=newpw,
                                         confirmpw=confirmpw,
                                         min_passwd_length=min_passwd_length,
                                         max_passwd_length=max_passwd_length)
        if qr[0]:
            pwscheme = None
            if 'store_password_in_plain_text' in form and settings.STORE_PASSWORD_IN_PLAIN_TEXT:
                pwscheme = 'PLAIN'
            passwd = iredpwd.generate_password_hash(qr[1], pwscheme=pwscheme)
        else:
            return qr

        # Hash/encrypt new password.
        updates['password'] = passwd
        updates['passwordlastchange'] = iredutils.get_gmttime()

        # Store plain password in another attribute.
        if settings.STORE_PLAIN_PASSWORD_IN_ADDITIONAL_ATTR:
            updates[settings.STORE_PLAIN_PASSWORD_IN_ADDITIONAL_ATTR] = newpw

    elif profile_type == 'greylisting':
        if settings.iredapd_enabled:
            qr = iredapd_greylist.update_greylist_settings_from_form(account=mail, form=form)
            return qr

    elif profile_type == 'advanced':
        # Get enabled/disabled services.
        enabledService = [str(v).lower()
                          for v in form.get('enabledService', [])
                          if v in ENABLED_SERVICES]
        disabledService = []

        # Append 'sieve', 'sievesecured' for dovecot-1.2.
        if 'enablemanagesieve' in enabledService:
            enabledService += ['enablesieve']
        else:
            disabledService += ['enablesieve']

        if 'enablemanagesievesecured' in enabledService:
            enabledService += ['enablesievesecured']
        else:
            disabledService += ['enablesievesecured']

        # Receiving email on server for this user
        if 'enabledeliver' in enabledService:
            enabledService += ['enablelda']
            enabledService += ['enablelmtp']

            # Mark `forwardings.active=1` to tell Postfix to accept emails for this user.
            try:
                conn.update("forwardings",
                            vars={"mail": mail},
                            where="address=$mail",
                            active=1)
            except Exception as e:
                return False, repr(e)
        else:
            disabledService += ['enablelda']
            disabledService += ['enablelmtp']

            # Mark `forwardings.active=0` to tell Postfix to NOT accept emails for this user.
            try:
                conn.update("forwardings",
                            vars={"mail": mail},
                            where="address=$mail",
                            active=0)
            except Exception as e:
                return False, repr(e)

        disabledService += [v for v in ENABLED_SERVICES if v not in enabledService]

        # Enable/disable services.
        for srv in enabledService:
            if srv in ["enablesogowebmail", "enablesogocalendar", "enablesogoactivesync"]:
                updates[srv] = "y"
            else:
                updates[srv] = 1

        for srv in disabledService:
            if srv in ["enablesogowebmail", "enablesogocalendar", "enablesogoactivesync"]:
                updates[srv] = "n"
            else:
                updates[srv] = 0

        # allow_nets
        _allow_nets = form.get('allow_nets', '').splitlines()
        allow_nets = [str(v) for v in _allow_nets if iredutils.is_ip_or_network(v)]
        if allow_nets:
            updates['allow_nets'] = ','.join(allow_nets)
        else:
            updates['allow_nets'] = None

        # Maildir path
        if session.get('is_global_admin'):
            # Get maildir related settings.
            storagebasedirectory = str(form.get('storageBaseDirectory', ''))
            storagenode = str(form.get('storageNode', ''))
            maildir = str(form.get('mailMessageStore', ''))

            updates['storagebasedirectory'] = storagebasedirectory
            updates['storagenode'] = storagenode
            updates['maildir'] = maildir

    else:
        return True,

    # Update SQL db
    try:
        conn.update('mailbox',
                    vars={'username': mail},
                    where='username=$username',
                    **updates)

        # Handle the new sql column `mailbox.enableimaptls` introduced in
        # iRedMail-0.9.8, required by Dovecot-2.3.
        # Some sysadmin may forgot to add this new column, so we handle it
        # separately. and we remove this in 2 future iRedAdmin-Pro releases.
        # TODO remove this in 2 future iRedAdmin-Pro releases.
        if 'enableimapsecured' in updates:
            try:
                conn.update('mailbox',
                            vars={'username': mail},
                            where='username=$username',
                            enableimaptls=updates['enableimapsecured'])
            except:
                pass

        if 'enablepop3secured' in updates:
            try:
                conn.update('mailbox',
                            vars={'username': mail},
                            where='username=$username',
                            enablepop3tls=updates['enablepop3secured'])
            except:
                pass

        # Update session immediately after updating SQL.
        if profile_type == 'general':
            if 'domainGlobalAdmin' not in form and \
               session.get('username') == mail:
                session['is_global_admin'] = False

        log_activity(msg="Update user profile ({}): {}.".format(profile_type, mail),
                     admin=session.get('username'),
                     username=mail,
                     domain=domain,
                     event='update')

        return True, {'discarded_aliases': discarded_aliases}
    except Exception as e:
        return False, repr(e)


def update_preferences(conn, mail, form, profile_type='general'):
    mail = str(mail).lower()
    if not session['username'] == mail:
        raise web.seeother('/preferences?msg=PERMISSION_DENIED')

    domain = mail.split('@', 1)[-1]

    # Get domain profile, used to get disabled user preferences
    qr = sql_lib_domain.simple_profile(conn=conn,
                                       domain=domain,
                                       columns=['settings'])
    if qr[0]:
        domain_profile = qr[1]
    else:
        return qr

    domain_settings = sqlutils.account_settings_string_to_dict(domain_profile.get('settings', ''))
    disabled_user_preferences = domain_settings.get('disabled_user_preferences', [])

    if profile_type in disabled_user_preferences:
        raise web.seeother('/preferences?msg=PERMISSION_DENIED')

    # Pre-defined update key:value pairs
    updates = {'modified': iredutils.get_gmttime()}

    if profile_type == 'general':
        if 'personal_info' not in disabled_user_preferences:
            updates['name'] = form.get('cn', '')

        # Get preferred language: short lang code. e.g. en_US, de_DE.
        lang = form_utils.get_language(form)
        updates['language'] = lang

        # Update language immediately.
        if session.get('username') == mail and session.get('lang') != lang:
            session['lang'] = lang

        # Timezone
        tz_name = form_utils.get_timezone(form)
        if tz_name:
            sql_lib_general.update_user_settings(conn=conn,
                                                 mail=mail,
                                                 new_settings={'timezone': tz_name})

            if session['username'] == mail:
                session['timezone'] = TIMEZONES[tz_name]

    elif profile_type == 'forwarding':
        fwd_addresses = form.get('mailForwardingAddresses', '').splitlines()
        fwd_addresses = list({str(v).lower() for v in fwd_addresses if iredutils.is_email(v)})
        if 'savecopy' in form:
            fwd_addresses += [mail]

        qr = reset_forwardings(mail=mail, forwardings=fwd_addresses, conn=conn)
        return qr

    elif profile_type == 'password':
        newpw = web.safestr(form.get('newpw', ''))
        confirmpw = web.safestr(form.get('confirmpw', ''))

        db_settings = iredutils.get_settings_from_db()
        _min_passwd_length = db_settings['min_passwd_length']
        _max_passwd_length = db_settings['max_passwd_length']

        # Get password length limit from domain profile or global setting.
        min_passwd_length = domain_settings.get('min_passwd_length', _min_passwd_length)
        max_passwd_length = domain_settings.get('max_passwd_length', _max_passwd_length)

        # Verify new passwords.
        qr = iredpwd.verify_new_password(newpw=newpw,
                                         confirmpw=confirmpw,
                                         min_passwd_length=min_passwd_length,
                                         max_passwd_length=max_passwd_length)

        if qr[0]:
            pwscheme = None
            if 'store_password_in_plain_text' in form and settings.STORE_PASSWORD_IN_PLAIN_TEXT:
                pwscheme = 'PLAIN'
            passwd = iredpwd.generate_password_hash(qr[1], pwscheme=pwscheme)
        else:
            return qr

        updates['password'] = passwd
        updates['passwordlastchange'] = iredutils.get_gmttime()

        # Always store plain password in another attribute.
        if settings.STORE_PLAIN_PASSWORD_IN_ADDITIONAL_ATTR:
            updates[settings.STORE_PLAIN_PASSWORD_IN_ADDITIONAL_ATTR] = newpw

    # Update SQL db
    try:
        conn.update('mailbox',
                    vars={'username': mail},
                    where='username=$username',
                    **updates)

        log_activity(msg="[self-service] Update profile ({}): {}.".format(profile_type, mail),
                     admin=mail,
                     username=mail,
                     domain=domain,
                     event='update')

        return True,
    except Exception as e:
        return False, repr(e)


def get_user_alias_addresses(mail, conn=None):
    """Get per-user alias addresses of given mail user.
    Returns tuple (True, [...]) or (False, '<error>').

    @mail -- user mail address
    @conn -- sql connection cursor
    """
    if not iredutils.is_email(mail):
        return False, 'INVALID_MAIL'

    if not conn:
        _wrap = SQLWrap()
        conn = _wrap.conn

    try:
        qr = conn.select('forwardings',
                         vars={'mail': mail},
                         what='address',
                         where='forwarding=$mail AND is_alias=1')
        if qr:
            _addresses = []

            for i in qr:
                _addr = str(i.address).lower()
                _addresses.append(_addr)

            _addresses.sort()
            return True, _addresses
        else:
            return True, []
    except Exception as e:
        return False, repr(e)


def get_bulk_user_alias_addresses(mails, conn=None):
    """Get per-user alias addresses of given mail users.

    @mails -- a list/tuple/set of user mail addresses
    @conn -- sql connection cursor
    """
    alias_addresses = {}

    mails = [str(i).lower() for i in mails if iredutils.is_email(i)]
    if not mails:
        return True, alias_addresses

    if not conn:
        _wrap = SQLWrap()
        conn = _wrap.conn

    try:
        qr = conn.select('forwardings',
                         vars={'addresses': mails},
                         what='address, forwarding',
                         where='forwarding IN $addresses AND is_alias=1')
        for r in qr:
            _user = str(r.forwarding).lower()
            _alias = str(r.address).lower()

            if _user in alias_addresses:
                alias_addresses[_user].append(_alias)
            else:
                alias_addresses[_user] = [_alias]

        return True, alias_addresses
    except Exception as e:
        return False, repr(e)


def get_user_forwardings(mail, conn=None):
    """Get mail forwarding addresses of given mail user.
    Returns (True, [<mail>, <mail>, ...]) or (False, '<error>').

    @mail -- user mail address
    @conn -- sql connection cursor
    """
    _forwardings = []

    if not iredutils.is_email(mail):
        return True, _forwardings

    if not conn:
        _wrap = SQLWrap()
        conn = _wrap.conn

    try:
        qr = conn.select('forwardings',
                         vars={'address': mail},
                         what='forwarding',
                         where='address=$address AND is_forwarding=1')

        for r in qr:
            _addr = str(r.forwarding).lower()
            _forwardings.append(_addr)

        _forwardings.sort()
        return True, _forwardings
    except Exception as e:
        return False, repr(e)


def get_bulk_user_forwardings(mails, conn=None):
    """Get mail forwarding addresses of given mail users.

    @mails -- a list/tuple/set of user mail addresses
    @conn -- sql connection cursor
    """
    user_forwardings = {}

    mails = [str(i).lower() for i in mails if iredutils.is_email(i)]
    if not mails:
        return True, user_forwardings

    if not conn:
        _wrap = SQLWrap()
        conn = _wrap.conn

    try:
        qr = conn.select('forwardings',
                         vars={'addresses': mails},
                         what='address,forwarding',
                         where='address IN $addresses AND is_forwarding=1')

        for r in qr:
            _user = str(r.address).lower()
            _forwarding = str(r.forwarding).lower()

            if _user in user_forwardings:
                user_forwardings[_user].append(_forwarding)
            else:
                user_forwardings[_user] = [_forwarding]

        return True, user_forwardings
    except Exception as e:
        return False, repr(e)


def get_assigned_aliases(mail, conn=None):
    """Get assigned mail aliases of given user.

    :param mail: mail address
    :param conn: sql connection cursor
    """
    if not iredutils.is_email(mail):
        return True, []

    if not conn:
        _wrap = SQLWrap()
        conn = _wrap.conn

    _groups = []
    try:
        qr = conn.select('forwardings',
                         vars={'mail': mail},
                         what='address',
                         where='forwarding=$mail AND is_list=1',
                         group='address')

        for r in qr:
            _addr = str(r.address).lower()
            _groups.append(_addr)

        _groups.sort()
        return True, _groups
    except Exception as e:
        return False, repr(e)


def get_bulk_user_assigned_groups(mails, conn=None):
    """Get email addresses of mail alias accounts which have given users as a
    member.

    @mails -- a list/tuple/set of mail addresses of mail users
    @conn -- sql connection cursor
    """
    _groups = {}

    mails = [str(i).lower() for i in mails if iredutils.is_email(i)]
    if not mails:
        return True, _groups

    if not conn:
        _wrap = SQLWrap()
        conn = _wrap.conn

    try:
        qr = conn.select('forwardings',
                         vars={'mails': mails},
                         what='address, forwarding',
                         where='forwarding IN $mails AND is_list=1')

        for r in qr:
            _group = str(r.address).lower()
            _user = str(r.forwarding).lower()

            if _user in _groups:
                _groups[_user].append(_group)
            else:
                _groups[_user] = [_group]

        return True, _groups
    except Exception as e:
        return False, repr(e)


def reset_aliases(mail, aliases=None, conn=None):
    """Reset per-user alias addresses. if @aliases is empty of None, all
    per-user aliases will be removed."""
    domain = mail.split('@', 1)[-1]

    _addresses = {str(i).lower()
                  for i in aliases
                  if iredutils.is_email(i) and i.endswith('@' + domain)}

    # Remove self
    _addresses.discard(mail)

    if not conn:
        _wrap = SQLWrap()
        conn = _wrap.conn

    # Remove all per-user alias addresses first
    try:
        conn.delete('forwardings',
                    vars={'mail': mail},
                    where='forwarding=$mail AND is_alias=1')
    except Exception as e:
        return False, repr(e)

    # Return if no need to reset
    if not _addresses:
        return True,

    # Get existing mail addresses
    qr = sql_lib_general.filter_existing_emails(mails=_addresses, conn=conn)
    _existings = qr['exist']

    # Remove existing addresses, use non-existing addresses
    _non_existings = [v for v in _addresses if v not in _existings]
    if not _non_existings:
        return True,

    v = []
    for i in _non_existings:
        v += [{'address': i,
               'forwarding': mail,
               'domain': domain,
               'dest_domain': mail.split('@', 1)[-1],
               'is_alias': 1,
               'active': 1}]

    try:
        conn.multiple_insert('forwardings', values=v)
        return True,
    except Exception as e:
        return False, repr(e)


def update_aliases(mail, new=None, removed=None, conn=None):
    """Add new per-user alias addresses defined in @new_aliases to user,
    remove existing aliases defined in @removed_aliases."""
    domain = mail.split('@', 1)[-1]

    _new = set()
    if new:
        _new = {str(i).lower()
                for i in new
                if i.endswith('@' + domain) and iredutils.is_email(i)}

    _removed = []
    if removed:
        _removed = [str(i).lower() for i in removed if iredutils.is_email(i)]

    if not (_new or _removed):
        return True, 'NO_VALID_ALIAS_ADDRESS'

    if not conn:
        _wrap = SQLWrap()
        conn = _wrap.conn

    if _new:
        # Remove self
        _new.discard(mail)

        # Query and exclude existing addresses
        try:
            qr = sql_lib_general.filter_existing_emails(mails=_new, conn=conn)
            _existings = qr['exist']
            _new = _new - set(_existings)
        except Exception as e:
            return False, repr(e)

        # Exclude addresses in _removed from _new
        if _removed:
            for i in _removed:
                _new.discard(i)

        if _new:
            # Add new per-user alias addresses by inserting a new record
            for addr in _new:
                try:
                    conn.insert('forwardings',
                                address=addr,
                                forwarding=mail,
                                domain=domain,
                                dest_domain=mail.split('@', 1)[-1],
                                is_alias=1,
                                active=1)
                except Exception as e:
                    # We already exclude existing addresses, so no more
                    # error caused by duplicate sql record, it must be
                    # something serious.
                    return False, repr(e)

    if _removed:
        try:
            conn.delete('forwardings',
                        vars={'removed': _removed, 'mail': mail},
                        where='address IN $removed AND forwarding=$mail')
        except Exception as e:
            return False, repr(e)

    return True,


def get_basic_user_profiles(domain,
                            columns=None,
                            first_char=None,
                            page=0,
                            disabled_only=False,
                            email_only=False,
                            with_last_login=False,
                            with_used_quota=False,
                            conn=None):
    """Get basic user profiles under given domain.

    Return data:
        (True, [{'mail': 'list@domain.com',
                 'name': '...',
                 ...other profiles in `vmail.maillists` table...
                 }])
    """
    domain = web.safestr(domain).lower()
    if not iredutils.is_domain(domain):
        raise web.seeother('/domains?msg=INVALID_DOMAIN_NAME')

    sql_vars = {'domain': domain}

    if columns:
        sql_what = ','.join(columns)
    else:
        if email_only:
            sql_what = 'username'
        else:
            sql_what = '*'

    if email_only:
        sql_what = 'username'

    additional_sql_where = ''
    if first_char:
        additional_sql_where = ' AND address LIKE %s' % web.sqlquote(first_char.lower() + '%')

    if disabled_only:
        additional_sql_where = ' AND active=0'

    # Get basic profiles
    try:
        if not conn:
            _wrap = SQLWrap()
            conn = _wrap.conn

        if page:
            qr = conn.select('mailbox',
                             vars=sql_vars,
                             what=sql_what,
                             where='domain=$domain %s' % additional_sql_where,
                             order='username ASC',
                             limit=settings.PAGE_SIZE_LIMIT,
                             offset=(page - 1) * settings.PAGE_SIZE_LIMIT)
        else:
            qr = conn.select('mailbox',
                             vars=sql_vars,
                             what=sql_what,
                             where='domain=$domain %s' % additional_sql_where,
                             order='username ASC')

        rows = list(qr)

        emails = []
        if email_only or with_last_login or with_used_quota:
            emails = [str(i.username).lower() for i in rows]

        if email_only:
            return True, emails
        else:
            if with_last_login:
                last_logins = sql_lib_general.get_account_last_login(accounts=emails)

                for row in rows:
                    email = row.username

                    _epoch_seconds = {
                        "imap": 0,
                        "pop3": 0,
                        "lda": 0,
                    }

                    if email in last_logins:
                        i = last_logins[email]
                        if i["imap"]:
                            _epoch_seconds["imap"] = i["imap"]

                        if i["pop3"]:
                            _epoch_seconds["pop3"] = i["pop3"]

                        if i["lda"]:
                            _epoch_seconds["lda"] = i["lda"]

                    row['last_login'] = _epoch_seconds

            if with_used_quota and emails:
                used_quota_info = {}
                qr = conn.select('used_quota',
                                 vars={"emails": emails},
                                 what="username, bytes, messages",
                                 where='username IN $emails',
                                 order='username ASC')
                for i in qr:
                    used_quota_info[i.username] = {"bytes": i.bytes, "messages": i.messages}

                for row in rows:
                    email = row.username
                    used_bytes = 0
                    used_messages = 0

                    if email in used_quota_info:
                        used_bytes = used_quota_info[email]["bytes"]
                        used_messages = used_quota_info[email]["messages"]

                    row["used_quota"] = {"bytes": used_bytes, "messages": used_messages}

        return True, rows
    except Exception as e:
        return False, repr(e)


@decorators.api_require_domain_access
def api_update_profile(mail, form, conn=None):
    """Update user profile.

    Optional form parameters:

    @name - common name (or, display name)
    @password - set new password for user
    @password_hash - set new password to given hashed password
    @quota - mailbox quota for this user (in MB).
    @accountStatus - enable or disable user. possible value is: active, disabled.
    @language - set preferred language of web UI
    @employeeid - set employee id
    @transport - set per-user transport
    @isGlobalAdmin -- promote user to be a global admin
    @forwarding -- set per-user mail forwarding addresseses
    @addForwarding -- add per-user mail forwarding addresses
    @removeForwarding -- remove existing per-user mail forwarding addresses
    @senderBcc -- set per-user bcc for outbound emails
    @recipientBcc -- set per-user bcc for inbound emails
    @aliases -- reset per-user alias addresses
    @addAlias -- add new per-user alias addresses
    @removeAlias -- remove existing per-user alias addresses
    @maildir -- full maildir path of the mailbox
    """
    mail = str(mail).lower()
    domain = mail.split('@', 1)[-1]

    if not conn:
        _wrap = SQLWrap()
        conn = _wrap.conn

    if not session.get('is_global_admin'):
        redirect_if_user_is_global_admin(conn=conn, mail=mail)

    params = {}

    # Name
    kv = form_utils.get_form_dict(form=form, input_name='name')
    params.update(kv)

    # Password
    if 'password' in form:
        qr = api_utils.get_form_password_dict(form=form,
                                              domain=domain,
                                              input_name='password')
        if qr[0]:
            params['password'] = qr[1]['pw_hash']
            params['passwordlastchange'] = iredutils.get_gmttime()
        else:
            return qr
    elif 'password_hash' in form:
        _pw_hash = form.get('password_hash', '').strip()
        params['password'] = _pw_hash
        params['passwordlastchange'] = iredutils.get_gmttime()

    # Account status
    kv = form_utils.get_form_dict(form,
                                  input_name='accountStatus',
                                  key_name='active')
    params.update(kv)

    # Language
    kv = form_utils.get_form_dict(form,
                                  input_name='language',
                                  to_string=True)
    params.update(kv)

    # Employee ID
    kv = form_utils.get_form_dict(form,
                                  input_name='employeeid',
                                  to_string=True)
    params.update(kv)

    # Transport
    kv = form_utils.get_form_dict(form,
                                  input_name='transport',
                                  to_string=True)
    params.update(kv)

    # Set quota
    if 'quota' in form:
        quota = str(form.get('quota', 0)).strip()
        qr = sql_lib_domain.assign_given_mailbox_quota(domain=domain,
                                                       quota=quota,
                                                       reset_user_quota=True,
                                                       user=mail)
        if qr[0]:
            quota = qr[1]
            params['quota'] = quota
        else:
            return qr

    # domainGlobalAdmin
    if 'isGlobalAdmin' in form:
        _v = form_utils.get_single_value(form=form,
                                         input_name='isGlobalAdmin',
                                         default_value='no',
                                         to_string=True)
        if _v == 'yes':
            promote_users_to_be_global_admin(mails=[mail],
                                             promote=True,
                                             conn=conn)
        else:
            promote_users_to_be_global_admin(mails=[mail],
                                             promote=False,
                                             conn=conn)

    # Mail forwarding addresses.
    if 'forwarding' in form:
        _fwd_addresses = form_utils.get_multi_values_from_api(form=form,
                                                              input_name='forwarding',
                                                              to_string=True,
                                                              to_lowercase=True,
                                                              is_email=True)

        qr = reset_forwardings(mail=mail,
                               forwardings=_fwd_addresses,
                               conn=conn)

        if not qr[0]:
            return qr
    else:
        # handle `addForwarding` and `removeForwarding`
        _forwardings = []

        if ('addForwarding' in form) or ('removeForwarding' in form):
            _qr = get_user_forwardings(mail=mail, conn=conn)
            if _qr[0]:
                _forwardings = _qr[1]
            else:
                return _qr

            if 'addForwarding' in form:
                _v = form_utils.get_multi_values_from_api(form=form,
                                                          input_name='addForwarding',
                                                          to_string=True,
                                                          is_email=True)
                _forwardings += _v

            if 'removeForwarding' in form:
                _v = form_utils.get_multi_values_from_api(form=form,
                                                          input_name='removeForwarding',
                                                          to_string=True,
                                                          is_email=True)
                _forwardings = [v for v in _forwardings if v not in _v]

            _forwardings = list(set(_forwardings))

            _qr = reset_forwardings(mail=mail,
                                    forwardings=_forwardings,
                                    conn=conn)

            if not _qr[0]:
                return _qr

    # BCC. only one bcc address is allowed.
    _sbcc = None
    _rbcc = None
    # User requested to remove all existing bcc addresses.
    _empty_sbcc = False
    _empty_rbcc = False
    if 'senderBcc' in form:
        _sbcc = form_utils.get_single_value(form,
                                            input_name='senderBcc',
                                            to_lowercase=True,
                                            is_email=True)
        if not _sbcc:
            _empty_sbcc = True

    if 'recipientBcc' in form:
        _rbcc = form_utils.get_single_value(form,
                                            input_name='recipientBcc',
                                            to_lowercase=True,
                                            is_email=True)

        if not _rbcc:
            _empty_rbcc = True

    if _sbcc or _rbcc or _empty_sbcc or _empty_rbcc:
        # BCC must handle alias domains.
        bcc_alias_domains = [domain]

        # Get all alias domains.
        _qr = sql_lib_domain.get_all_alias_domains(domain=domain,
                                                   name_only=True,
                                                   conn=conn)
        if _qr[0]:
            bcc_alias_domains += _qr[1]

        bcc_alias_users = list({mail.split('@', 1)[0] + '@' + d for d in bcc_alias_domains})
        del bcc_alias_domains

        if _sbcc or _empty_sbcc:
            try:
                # Delete bcc records first.
                for u in bcc_alias_users:
                    conn.delete('sender_bcc_user',
                                vars={'username': u},
                                where='username=$username')
            except Exception as e:
                return False, repr(e)

        if _rbcc or _empty_rbcc:
            try:
                conn.delete('recipient_bcc_user',
                            vars={'username': u},
                            where='username=$username')
            except Exception as e:
                return False, repr(e)

        if _sbcc:
            # Insert new records.
            try:
                for u in bcc_alias_users:
                    conn.insert('sender_bcc_user',
                                username=u,
                                bcc_address=_sbcc,
                                domain=u.split('@', 1)[-1],
                                created=iredutils.get_gmttime(),
                                modified=iredutils.get_gmttime(),
                                active=1)
            except Exception as e:
                return False, repr(e)

        if _rbcc:
            try:
                for u in bcc_alias_users:
                    conn.insert('recipient_bcc_user',
                                username=u,
                                bcc_address=_rbcc,
                                domain=u.split('@', 1)[-1],
                                created=iredutils.get_gmttime(),
                                modified=iredutils.get_gmttime(),
                                active=1)
            except Exception as e:
                return False, repr(e)

    # Per-user alias addresses
    if 'aliases' in form:
        _v = form_utils.get_single_value(form=form,
                                         input_name='aliases',
                                         default_value='',
                                         to_lowercase=True,
                                         to_string=True)
        _v = _v.strip(' ').split(',')
        qr = reset_aliases(mail=mail, aliases=_v, conn=conn)
        if not qr[0]:
            return qr

    else:
        # Add new aliases
        _new = []

        # Remove existing aliases
        _removed = []

        # Add/remove per-user aliases
        if 'addAlias' in form:
            _v = form_utils.get_single_value(form=form,
                                             input_name='addAlias',
                                             to_lowercase=True,
                                             to_string=True)
            _v = _v.strip(' ').split(',')
            _new = [i for i in _v if iredutils.is_email(i)]

        if 'removeAlias' in form:
            _v = form_utils.get_single_value(form=form,
                                             input_name='removeAlias',
                                             to_lowercase=True,
                                             to_string=True)
            _v = _v.strip(' ').split(',')
            _removed = [i for i in _v if iredutils.is_email(i)]

        if _new or _removed:
            qr = update_aliases(mail=mail,
                                new=_new,
                                removed=_removed,
                                conn=conn)

            if not qr[0]:
                return qr

    # Per-user enabled mail services
    # NOTE: it requires SQL column `enable<service>` in `vmail.mailbox`.
    if 'services' in form:
        _v = form_utils.get_multi_values_from_api(form=form, input_name='services')

        # Disable all mail services
        for i in ENABLED_SERVICES:
            params[i] = 0

        # Enable requested services
        for i in _v:
            _srv = 'enable' + i
            params[_srv] = 1

    else:
        if 'addService' in form:
            _v = form_utils.get_multi_values_from_api(form=form, input_name='addService')
            for i in _new:
                _srv = 'enable' + i
                params[_srv] = 1

        if 'removeService' in form:
            _v = form_utils.get_multi_values_from_api(form=form, input_name='removeService')

            for i in _v:
                _srv = 'enable' + i
                params[_srv] = 0

    # Get mailbox format and folder.
    _mailbox_format = form.get('mailboxFormat', None)
    if _mailbox_format:
        if iredutils.is_valid_mailbox_format(_mailbox_format):
            params['mailboxformat'] = _mailbox_format

    _mailbox_folder = form.get('mailboxFolder', '')
    if iredutils.is_valid_mailbox_folder(_mailbox_folder):
        params['mailboxfolder'] = _mailbox_folder

    _mailbox_maildir = form.get('maildir', '').lower().rstrip('/')
    if _mailbox_maildir and os.path.isabs(_mailbox_maildir):
        # Split storageBaseDirectory and storageNode
        _splited = _mailbox_maildir.rstrip('/').split('/')
        params['storagebasedirectory'] = '/' + _splited[0]
        params['storagenode'] = _splited[1]
        params['maildir'] = '/'.join(_splited[2:])

    if not params:
        return True,

    try:
        conn.update('mailbox',
                    vars={'mail': mail},
                    where='username=$mail',
                    **params)

        try:
            # Log updated parameters and values if possible
            msg = str(params)
        except:
            msg = ', '.join(params)

        log_activity(msg="Update user profile: {} -> {}".format(mail, msg),
                     admin=session.get('username'),
                     username=mail,
                     domain=domain,
                     event='update')

        return True,
    except Exception as e:
        return False, repr(e)
