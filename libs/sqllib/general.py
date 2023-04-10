# Author: Zhang Huangbin <zhb@iredmail.org>

# WARNING: this file/module will be imported by other modules under
#          libs/sqllib/, to avoid chained import loop, do not import any
#          other modules under libs/sqllib/ in this file.

from typing import Dict, Tuple
import web
from libs import iredutils
from libs.logger import logger, log_traceback, log_activity
from libs.sqllib import SQLWrap, sqlutils
import settings

session = web.config.get('_session', {})


def is_global_admin(admin, conn=None) -> bool:
    if not admin:
        return False

    if admin == session.get('username'):
        if session.get('is_global_admin'):
            return True
        else:
            return False

    # Not logged admin.
    try:
        if not conn:
            _wrap = SQLWrap()
            conn = _wrap.conn

        qr = conn.select('domain_admins',
                         vars={'username': admin, 'domain': 'ALL'},
                         what='username',
                         where='username=$username AND domain=$domain',
                         limit=1)
        if qr:
            return True
        else:
            return False
    except:
        return False


def is_domain_admin(domain, admin=None, conn=None) -> bool:
    if (not iredutils.is_domain(domain)) or (not iredutils.is_email(admin)):
        return False

    if not admin:
        admin = session.get('username')

    if admin == session.get('username') and session.get('is_global_admin'):
        return True

    try:
        if not conn:
            _wrap = SQLWrap()
            conn = _wrap.conn

        qr = conn.select(
            'domain_admins',
            vars={'domain': domain, 'username': admin},
            what='username',
            where='domain=$domain AND username=$username AND active=1',
            limit=1,
        )

        if qr:
            return True
        else:
            return False
    except:
        return False


def is_ml_owner(ml, owner, conn=None) -> bool:
    if (not iredutils.is_email(ml)) or (not iredutils.is_email(owner)):
        return False

    try:
        if not conn:
            _wrap = SQLWrap()
            conn = _wrap.conn

        qr = conn.select(
            'maillist_owners',
            vars={'address': ml, 'owner': owner},
            what='address',
            where='address=$address AND owner=$owner',
            limit=1,
        )

        if qr:
            return True
        else:
            return False
    except:
        return False


def is_ml_moderator(ml, moderator, conn=None) -> bool:
    if (not iredutils.is_email(ml)) or (not iredutils.is_email(moderator)):
        return False

    try:
        if not conn:
            _wrap = SQLWrap()
            conn = _wrap.conn

        qr = conn.select(
            'moderators',
            vars={'address': ml, 'moderator': moderator},
            what='address',
            where='address=$address AND moderator=$moderator',
            limit=1,
        )

        if qr:
            return True
        else:
            return False
    except:
        return False


def is_ml_owner_or_moderator(ml, user, conn=None) -> bool:
    if is_ml_owner(ml=ml, owner=user, conn=conn):
        return True

    return is_ml_moderator(ml=ml, moderator=user, conn=conn)


def is_email_exists(mail, conn=None) -> bool:
    # Return True if account is invalid or exist.
    if not iredutils.is_email(mail):
        return True

    mail = iredutils.strip_mail_ext_address(mail)

    if not conn:
        _wrap = SQLWrap()
        conn = _wrap.conn

    try:
        # `forwardings` table has email addr of mail user account and alias account.
        qr = conn.select('forwardings',
                         vars={'mail': mail},
                         what='address',
                         where='address=$mail',
                         limit=1)

        if qr:
            return True

        # Check `alias` for alias account which doesn't have any member.
        qr = conn.select('alias',
                         vars={'mail': mail},
                         what='address',
                         where='address=$mail',
                         limit=1)
        if qr:
            return True

        return False
    except Exception:
        return True


def __is_account_exists(account, account_type, conn=None) -> bool:
    """Check whether mail alias account exists."""
    if account_type == 'domain':
        if not iredutils.is_domain(account):
            return True

        account = account.lower()
    else:
        if not iredutils.is_email(account):
            return False

        account = iredutils.strip_mail_ext_address(account)

    # {<account_type: [(<sql-table>, <sql-column-name>), ...]}
    _maps = {
        "domain": [
            ("domain", "domain"),
            ("alias_domain", "alias_domain"),
        ],
        "user": [("mailbox", "username")],
        "alias": [("alias", "address")],
        "ml": [("maillists", "address")],
    }

    if account_type not in _maps:
        return False

    if not conn:
        _wrap = SQLWrap()
        conn = _wrap.conn

    try:
        for (_table, _column) in _maps[account_type]:
            qr = conn.select(_table,
                             vars={'account': account},
                             what=_column,
                             where='%s=$account' % _column,
                             limit=1)

            if qr:
                return True
    except:
        log_traceback()
        return False

    return False


def is_domain_exists(domain, conn=None) -> bool:
    return __is_account_exists(account=domain, account_type='domain', conn=conn)


def is_alias_exists(mail, conn=None) -> bool:
    return __is_account_exists(account=mail, account_type='alias', conn=conn)


def is_ml_exists(mail, conn=None) -> bool:
    return __is_account_exists(account=mail, account_type='ml', conn=conn)


def __is_active_account(account_type, account, conn=None) -> bool:
    """Check whether given account is active."""
    account = str(account).lower()

    if not conn:
        _wrap = SQLWrap()
        conn = _wrap.conn

    # {<account_type>: (<table>, <column>)}
    _maps = {
        "user": ("mailbox", "username"),
        "alias": ("alias", "address"),
        "ml": ("maillists", "address"),
        "domain": ("domain", "domain"),
        "admin": ("admin", "username"),
    }

    if account_type not in _maps:
        return False

    (_table, _column) = _maps[account_type]

    try:
        qr = conn.select(_table,
                         vars={'account': account},
                         what="active",
                         where="%s=$account AND active=1" % _column,
                         limit=1)

        if qr:
            return True
    except Exception as e:
        logger.error("Error while checking whether account is active: {}.".format(e))

    return False


def is_active_user(mail, conn=None) -> bool:
    return __is_active_account(account_type='user', account=mail, conn=conn)


def get_sender_relayhost(sender, conn=None):
    """Get relayhost of specified sender.

    @sender - must be an email address or a domain name prefixed with '@'.
    """
    relayhost = ''

    # Make sure we have correct sender address.
    if iredutils.is_email(sender):
        pass
    elif sender.startswith('@'):
        # If sender is not '@domain.com', return empty value.
        d = sender.lstrip('@')
        if not iredutils.is_domain(d):
            return False, 'INVALID_ACCOUNT'
    elif iredutils.is_domain(sender):
        sender = '@' + sender

    try:
        if not conn:
            _wrap = SQLWrap()
            conn = _wrap.conn

        qr = conn.select('sender_relayhost',
                         vars={'account': sender},
                         what='relayhost',
                         where='account = $account',
                         limit=1)
        if qr:
            relayhost = str(qr[0]['relayhost'])
    except Exception as e:
        logger.error(e)
        return False, repr(e)

    return True, relayhost


def update_sender_relayhost(account, relayhost, conn=None):
    """Update relayhost for specified (local) account (sender).

    @account -- could be an email address, or a domain name prefixed with '@'.
    """
    # Make sure we have correct account
    if iredutils.is_email(account):
        domain = account.split('@', 1)[-1]
    elif account.startswith('@'):
        d = account.lstrip('@')
        domain = d
        if not iredutils.is_domain(d):
            return False, 'INVALID_ACCOUNT'
    elif iredutils.is_domain(account):
        account = '@' + account
        domain = account
    else:
        return False, 'INVALID_ACCOUNT'

    if not conn:
        _wrap = SQLWrap()
        conn = _wrap.conn

    try:
        # Delete existing record first.
        conn.delete('sender_relayhost',
                    vars={'account': account},
                    where='account=$account')

        # Add new record
        if relayhost:
            conn.insert('sender_relayhost',
                        account=account,
                        relayhost=relayhost)

            log_activity(msg="Update per-account ({}) outbound relay to: {}".format(account, relayhost),
                         domain=domain,
                         username=account,
                         event='update')
        else:
            log_activity(msg="Delete per-account (%s) outbound relay." % account,
                         domain=domain,
                         username=account,
                         event='delete')

        return True,
    except Exception as e:
        return False, repr(e)


def filter_existing_emails(mails, account_type=None, conn=None):
    """
    Remove non-existing addresses in given list, return a list of existing ones.

    :param mails: list of email addresses
    :param account_type: user, alias, maillist.
    :param conn: sql connection cursor
    """
    exist = []
    nonexist = []

    mails = [i for i in mails if iredutils.is_email(i)]

    if not mails:
        return {'exist': exist, 'nonexist': nonexist}

    # A dict with email addresses without and with mail extension.
    d = {}
    for i in mails:
        _addr_without_ext = iredutils.strip_mail_ext_address(i)
        d[_addr_without_ext] = i

    emails_without_ext = list(d.keys())

    # {<account_type>: {'table': <sql_table_name>, 'column': <sql_column_name>}}
    _tbl_column_maps = {
        'user': [("forwardings", "address"), ("mailbox", "username")],
        'alias': [("alias", "address")],
        'maillist': [("maillists", "address")],
    }

    if not conn:
        _wrap = SQLWrap()
        conn = _wrap.conn

    try:
        _tbl_and_columns = []
        if account_type:
            _tbl_and_columns += _tbl_column_maps[account_type]
        else:
            for v in list(_tbl_column_maps.values()):
                _tbl_and_columns += v

        for (_table, _column) in _tbl_and_columns:
            # Removing verified addresses to query less values for better SQL
            # query performance.
            _pending_emails = [i for i in emails_without_ext if i not in exist]
            if not _pending_emails:
                break

            qr = conn.select(_table,
                             vars={'mails': _pending_emails},
                             what='%s' % _column,
                             where='%s IN $mails' % _column,
                             group='%s' % _column)

            if qr:
                for row in qr:
                    _addr = str(row[_column]).lower()
                    exist.append(d[_addr])

        exist = list(set(exist))
        nonexist = [d[k] for k in d if k not in exist]
    except:
        log_traceback()

    return {'exist': exist, 'nonexist': nonexist}


def filter_existing_aliases(mails, conn=None):
    return filter_existing_emails(mails=mails, account_type='alias', conn=conn)


def filter_existing_mailing_lists(mails, conn=None):
    return filter_existing_emails(mails=mails, account_type='maillist', conn=conn)


def filter_existing_domains(conn, domains):
    domains = [str(v).lower() for v in domains if iredutils.is_domain(v)]
    domains = list(set(domains))

    exist = []
    nonexist = []

    try:
        # Primary domains
        qr1 = conn.select('domain',
                          vars={'domains': domains},
                          what='domain',
                          where='domain IN $domains')

        # Alias domains
        qr2 = conn.select('alias_domain',
                          vars={'domains': domains},
                          what='alias_domain AS domain',
                          where='alias_domain IN $domains')

        qr = list(qr1) + list(qr2)
        if not qr:
            nonexist = domains
        else:
            for i in qr:
                exist.append(str(i['domain']).lower())

            nonexist = [d for d in domains if d not in exist]
    except:
        pass

    return {'exist': exist, 'nonexist': nonexist}


# Do not apply @decorators.require_domain_access
def get_domain_settings(domain, domain_profile=None, conn=None):
    domain = str(domain).lower()

    try:
        if not domain_profile:
            if not conn:
                _wrap = SQLWrap()
                conn = _wrap.conn

            qr = conn.select('domain',
                             vars={'domain': domain},
                             what='settings',
                             where='domain=$domain',
                             limit=1)

            if qr:
                domain_profile = list(qr)[0]
            else:
                return False, 'INVALID_DOMAIN_NAME'

        ps = domain_profile.get('settings', '')
        ds = sqlutils.account_settings_string_to_dict(ps)

        return True, ds
    except Exception as e:
        return False, repr(e)


def get_user_settings(mail, existing_settings=None, conn=None):
    """Return dict of per-user settings stored in SQL column: mailbox.settings.

    :param mail: full user email address.
    :param existing_settings: original value of sql column `mailbox.settings`.
    :param conn: sql connection cursor.
    """
    if not iredutils.is_email(mail):
        return False, 'INVALID_MAIL'

    if not conn:
        _wrap = SQLWrap()
        conn = _wrap.conn

    user_settings = {}

    # Get settings stored in sql column `mailbox.settings`
    if existing_settings:
        orig_settings = existing_settings
    else:
        try:
            qr = conn.select('mailbox',
                             vars={'username': mail},
                             what='settings',
                             where='username=$username',
                             limit=1)

            if qr:
                orig_settings = qr[0]['settings']
            else:
                return False, 'NO_SUCH_ACCOUNT'
        except Exception as e:
            return False, repr(e)

    if orig_settings:
        user_settings = sqlutils.account_settings_string_to_dict(orig_settings)

    return True, user_settings


def get_admin_settings(admin=None, existing_settings=None, conn=None) -> Tuple:
    """Return a dict of per-admin settings.

    :param admin: mail address of domain admin
    :param existing_settings: original value of sql column `settings`
    :param conn: SQL connection cursor
    """
    if not admin:
        admin = session.get('username')

    if not iredutils.is_email(admin):
        return False, 'INVALID_ADMIN'

    if not conn:
        _wrap = SQLWrap()
        conn = _wrap.conn

    account_settings = {}

    # Get settings stored in sql column `mailbox.settings`
    if existing_settings:
        orig_settings = existing_settings
    else:
        try:
            qr = conn.select('mailbox',
                             vars={'username': admin},
                             what='settings',
                             where='username=$username AND (isadmin=1 OR isglobaladmin=1)',
                             limit=1)

            if not qr:
                # Not a mail user
                qr = conn.select('admin',
                                 vars={'username': admin},
                                 what='settings',
                                 where='username=$username',
                                 limit=1)
                if not qr:
                    return False, 'INVALID_ADMIN'

            orig_settings = qr[0]['settings']
        except Exception as e:
            return False, repr(e)

    if orig_settings:
        account_settings = sqlutils.account_settings_string_to_dict(orig_settings)

    return True, account_settings


# Update SQL column `[domain|admin|mailbox].settings` in `vmail` database.
def __update_account_settings(conn,
                              account,
                              account_type='user',
                              exist_settings=None,
                              new_settings=None,
                              removed_settings=None):
    """Update account settings stored in SQL column `settings`.

    :param conn: SQL connection cursor
    :param account: the account you want to update. could be a domain, admin, user
    :param account_type: one of: domain, admin, user
    :param exist_settings: dict of account settings you already get from SQL
    :param new_settings: dict of the new settings you want to add
    :param removed_settings: list of the setting names you want to remove
    """
    account = str(account).lower()

    # Get current settings stored in SQL db
    if exist_settings:
        current_settings = exist_settings
    else:
        if account_type == 'user':
            qr = get_user_settings(mail=account, conn=conn)
        elif account_type == 'admin':
            qr = get_admin_settings(admin=account, conn=conn)
        elif account_type == 'domain':
            qr = get_domain_settings(domain=account, conn=conn)
        else:
            return False, 'UNKNOWN_ACCOUNT_TYPE'

        if qr[0]:
            current_settings = qr[1]
        else:
            current_settings = {}

    if new_settings:
        for (k, v) in list(new_settings.items()):
            current_settings[k] = v

    if removed_settings:
        for k in removed_settings:
            try:
                current_settings.pop(k)
            except:
                pass

    # Convert settings dict to string
    settings_string = sqlutils.account_settings_dict_to_string(current_settings)

    try:
        if account_type == 'user':
            conn.update('mailbox',
                        vars={'username': account},
                        where='username=$username',
                        settings=settings_string)
        elif account_type == 'admin':
            conn.update('admin',
                        vars={'username': account},
                        where='username=$username',
                        settings=settings_string)
        elif account_type == 'domain':
            conn.update('domain',
                        vars={'domain': account},
                        where='domain=$domain',
                        settings=settings_string)

        return True,
    except Exception as e:
        return False, repr(e)


def update_user_settings(conn,
                         mail,
                         exist_settings=None,
                         new_settings=None,
                         removed_settings=None):
    return __update_account_settings(conn=conn,
                                     account=mail,
                                     account_type='user',
                                     exist_settings=exist_settings,
                                     new_settings=new_settings,
                                     removed_settings=removed_settings)


def update_admin_settings(conn,
                          mail,
                          exist_settings=None,
                          new_settings=None,
                          removed_settings=None):
    return __update_account_settings(conn=conn,
                                     account=mail,
                                     account_type='admin',
                                     exist_settings=exist_settings,
                                     new_settings=new_settings,
                                     removed_settings=removed_settings)


def update_domain_settings(conn,
                           domain,
                           exist_settings=None,
                           new_settings=None,
                           removed_settings=None):
    return __update_account_settings(conn=conn,
                                     account=domain,
                                     account_type='domain',
                                     exist_settings=exist_settings,
                                     new_settings=new_settings,
                                     removed_settings=removed_settings)


def get_bcc_address(account, account_type, bcc_type, conn=None):
    """Get per-domain or per-user sender/recipient bcc address.

    :param account: domain name or user mail address.
    :param account_type: user, domain.
    :param bcc_type: sender, recipient.
    :param conn: SQL connection cursor.
    """
    sql_table = '{}_bcc_{}'.format(bcc_type, account_type)
    if account_type == 'domain':
        column = 'domain'
    elif account_type == 'user':
        column = 'username'
    else:
        return False, 'UNKNOWN_ACCOUNT_TYPE'

    if not conn:
        _wrap = SQLWrap()
        conn = _wrap.conn

    try:
        qr = conn.select(sql_table,
                         vars={'account': account},
                         what='bcc_address',
                         where='%s=$account' % column,
                         limit=1)

        if qr:
            addr = str(qr[0]['bcc_address']).lower()
            return True, addr
        else:
            return True, ''
    except Exception as e:
        return False, repr(e)


def __num_accounts_under_domain(domain, account_type, conn=None) -> int:
    num = 0

    if not iredutils.is_domain(domain):
        return num

    if not conn:
        _wrap = SQLWrap()
        conn = _wrap.conn

    # mapping of account types and sql table names
    mapping = {
        'user': 'mailbox',
        'alias': 'alias',
        'maillist': 'maillists',
    }
    sql_table = mapping[account_type]

    try:
        qr = conn.select(sql_table,
                         vars={'domain': domain},
                         what='COUNT(domain) AS total',
                         where='domain=$domain')

        if qr:
            num = qr[0].total
    except Exception as e:
        logger.error(e)

    return num


def num_users_under_domain(domain, conn=None) -> int:
    return __num_accounts_under_domain(domain=domain,
                                       account_type='user',
                                       conn=conn)


def num_aliases_under_domain(domain, conn=None) -> int:
    return __num_accounts_under_domain(domain=domain,
                                       account_type='alias',
                                       conn=conn)


def num_maillists_under_domain(domain, conn=None) -> int:
    return __num_accounts_under_domain(domain=domain,
                                       account_type='maillist',
                                       conn=conn)


def require_domain_ownership_verification(admin, conn=None) -> bool:
    if is_global_admin(admin=admin, conn=conn):
        return False

    qr = get_admin_settings(admin=admin, existing_settings=None, conn=conn)
    if not qr[0]:
        logger.error(qr)
        return True

    _as = qr[1]

    if _as.get('disable_domain_ownership_verification') == 'yes':
        return False

    return settings.REQUIRE_DOMAIN_OWNERSHIP_VERIFICATION


def export_managed_accounts(mail, domains=None, conn=None):
    """Export managed accounts.

    :param mail: admin email address
    :param domains: list/tuple/set of domain names
    :param conn: sql connection cursor
    """
    mail = str(mail).lower()

    if domains:
        domains = [str(d).lower() for d in domains if iredutils.is_domain(d)]

    if not conn:
        _wrap = SQLWrap()
        conn = _wrap.conn

    # A list of dict with domain name, display name, and more.
    # [
    #   {'domain': '<domain>',
    #    'name': '<name>',
    #    'total_users': <number>,
    #    'total_lists': <number>,
    #    'total_aliases': <number>,
    #    'users': [{'mail': '<mail>', 'name': '<name>', ...}, ...],
    #    'lists': [{'mail': '<mail>', 'name': '<name>', ...}, ...],
    #    'aliases': [{'mail': '<mail>', 'name': '<name>', ...}, ...]}
    #   ...
    #  ]
    #                            '
    _managed_domains = []

    # Get managed domains.
    try:
        if is_global_admin(admin=mail, conn=conn):
            # get all active domains
            if domains:
                qr = conn.select('domain',
                                 vars={'domains': domains},
                                 what='domain, description',
                                 where='active=1 AND domain IN $domains')
            else:
                qr = conn.select('domain',
                                 what='domain, description',
                                 where='active=1')
        else:
            sql_where = ''
            if domains:
                sql_where = 'AND domain_admins.domain IN $domains'

            qr = conn.query("""
                            SELECT domain.domain, domain.description
                              FROM domain
                         LEFT JOIN domain_admins ON (domain.domain=domain_admins.domain)
                             WHERE domain_admins.username=$admin %s
                          ORDER BY domain_admins.domain
                            """ % sql_where,
                            vars={'admin': mail})
    except Exception as e:
        return False, repr(e)

    if not qr:
        return True, []

    for r in qr:
        _domain = str(r['domain']).lower()
        _name = r.get('description', '')

        d = {
            'domain': _domain,
            'name': _name,
            'total_users': 0,
            'total_lists': 0,
            'total_aliases': 0,
            'users': [],
            'lists': [],
            'aliases': [],
        }

        # A dict of (account_type, sql_table_name, mail_column, name_column).
        _maps = [('users', 'mailbox', 'username', 'name'),
                 ('aliases', 'alias', 'address', 'name'),
                 ('lists', 'maillists', 'address', 'name')]

        # Get all mail users.
        for (_account_type, _sql_tbl, _sql_column_mail, _sql_column_name) in _maps:
            _qr = conn.select(_sql_tbl,
                              vars={'domain': _domain},
                              what='{}, {}'.format(_sql_column_mail, _sql_column_name),
                              where='domain=$domain AND active=1')

            for _r in _qr:
                d['total_' + _account_type] += 1

                _mail2 = str(_r[_sql_column_mail]).lower()
                _name2 = _r.get(_sql_column_name, '')
                d[_account_type] += [{'mail': _mail2, 'name': iredutils.bytes2str(_name2)}]

        _managed_domains.append(d)

    return True, _managed_domains


def get_account_used_quota(accounts, conn) -> Dict:
    """Return dict of account/quota size pairs.

    accounts -- must be list/tuple of email addresses.
    """
    if not accounts:
        return {}

    # Pre-defined dict of used quotas.
    #   {'user@domain.com': {'bytes': INTEGER, 'messages': INTEGER,}}
    used_quota = {}

    # Get used quota.
    try:
        qr = conn.select(settings.SQL_TBL_USED_QUOTA,
                         vars={'accounts': accounts},
                         where='username IN $accounts',
                         what='username, bytes, messages')

        for uq in qr:
            used_quota[uq.username] = {
                'bytes': uq.get('bytes', 0),
                'messages': uq.get('messages', 0),
            }
    except:
        pass

    return used_quota


def get_account_last_login(accounts, conn=None) -> Dict:
    """Return dict of account last login time.

    @accounts: must be list/tuple/set of full email addresses.
    """
    d = {}

    # Dovecot doesn't support storing user last login info in PGSQL (yet).
    if settings.backend == 'pgsql':
        return d

    if not accounts:
        return d

    # Get used quota.
    try:
        if not conn:
            _wrap = SQLWrap()
            conn = _wrap.conn

        qr = conn.select('last_login',
                         vars={'accounts': accounts},
                         where='username IN $accounts')

        for row in qr:
            d[row.username] = dict(row)

    except Exception as e:
        logger.error(e)

    return d


def get_all_last_logins(domain: str, conn=None) -> Dict:
    """Return dict of last login times of all users under given domain.

    Sample result:

    {"<email>": {"active": True,        # True means account is active.
                 "forwardings": [],     # List of forwarding addresses.
                 "name": "John Smith",
                 "imap": 1625146622,    # 0 means no login yet.
                 "pop3": 0,
                 "lda":  1625146622},
     ...
    }
    """
    d = {}

    # Requires Dovecot-2.3.16+ for UPSERT support (used by last_login plugin)
    # in PGSQL.
    if settings.backend == 'pgsql':
        return d

    domain = domain.lower()

    try:
        if not conn:
            _wrap = SQLWrap()
            conn = _wrap.conn

        # Get all users' display names and email addresses.
        qr = conn.select("mailbox",
                         vars={"domain": domain},
                         what="name,username,active",
                         where="domain=$domain")

        for r in qr:
            email = iredutils.bytes2str(r.username).lower()
            name = iredutils.bytes2str(r.name)

            d[email] = {
                "active": (r.active == 1),
                "forwardings": [],
                "name": name,
                "imap": 0,
                "pop3": 0,
                "lda": 0,
            }

        # Get users who have mail forwardings.
        qr = conn.select("forwardings",
                         vars={"domain": domain},
                         what="address, forwarding",
                         where="domain=$domain AND address<>forwarding")

        for r in qr:
            email = iredutils.bytes2str(r.address).lower()
            addr = iredutils.bytes2str(r.forwarding).lower()

            if email in d and addr:
                d[email]["forwardings"].append(addr)

        # Get all last logins.
        qr = conn.select('last_login',
                         vars={'domain': domain},
                         what="username,imap,pop3,lda",
                         where="domain=$domain")

        for r in qr:
            email = iredutils.bytes2str(r.username).lower()

            if email in d:
                d[email]["imap"] = r.imap or 0
                d[email]["pop3"] = r.pop3 or 0
                d[email]["lda"] = r.lda or 0

    except Exception as e:
        logger.error(e)

    return d


def get_first_char_of_all_accounts(domain,
                                   account_type,
                                   conn=None):
    """Get first character of accounts under given domain.

    @domain - must be a valid domain name.
    @account_type - could be one of: user, ml, alias.
    @conn - SQL connection cursor
    """
    if not conn:
        _wrap = SQLWrap()
        conn = _wrap.conn

    type_map = {
        'user': {'table': 'mailbox', 'column': 'username'},
        'alias': {'table': 'alias', 'column': 'address'},
        'ml': {'table': 'maillists', 'column': 'address'},
    }

    _table = type_map[account_type]['table']
    _column = type_map[account_type]['column']

    chars = []
    try:
        qr = conn.select(_table,
                         vars={'domain': domain},
                         what="SUBSTRING({} FROM 1 FOR 1) AS first_char".format(_column),
                         where='domain=$domain',
                         group='first_char')

        if qr:
            chars = [str(i.first_char).upper() for i in qr]
            chars.sort()

        return True, chars
    except Exception as e:
        log_traceback()
        return False, repr(e)
