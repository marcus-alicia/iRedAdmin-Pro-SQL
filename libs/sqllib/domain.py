# Author: Zhang Huangbin <zhb@iredmail.org>

import web

import settings
from libs import iredutils, form_utils
from libs.logger import logger, log_activity

from libs.sqllib import SQLWrap, decorators, sqlutils
from libs.sqllib import general as sql_lib_general
from libs.sqllib import admin as sql_lib_admin

from libs.amavisd import get_wblist_from_form, wblist as lib_wblist

from libs.panel import domain_ownership

session = web.config.get('_session', {})

if settings.iredapd_enabled:
    from libs.iredapd import throttle as iredapd_throttle
    from libs.iredapd import greylist as iredapd_greylist
    from libs.iredapd import utils as iredapd_utils

if settings.amavisd_enable_policy_lookup:
    from libs.amavisd.utils import delete_policy_accounts

# Mail service names manageable in per-domain profile page.
# must sync with
#   - Jinja2 template file: templates/default/macros/general.html
#   - libs/sqllib/domain.py
#   - libs/ldaplib/domain.py
AVAILABLE_DOMAIN_DISABLED_MAIL_SERVICES = [
    'smtp', 'smtpsecured',
    'pop3', 'pop3secured',
    'imap', 'imapsecured',
    'managesieve', 'managesievesecured',
    'sogo',
]


def get_all_domains(conn=None, columns=None, name_only=False):
    """Get all domains. Return (True, [records])."""
    if columns:
        sql_what = ','.join(columns)
    else:
        if name_only:
            sql_what = 'domain'
        else:
            sql_what = '*'

    try:
        if not conn:
            _wrap = SQLWrap()
            conn = _wrap.conn

        result = conn.select('domain', what=sql_what, order='domain ASC')

        if name_only:
            domain_names = [str(r.domain).lower() for r in result]
            return True, domain_names
        else:
            return True, list(result)
    except Exception as e:
        return False, repr(e)


def get_all_managed_domains(conn=None,
                            columns=None,
                            name_only=False,
                            disabled_only=False):
    """Get all managed domains.

    Returned values:

    - (True, [records])
    - (True, [<domain_name>, <domain_name>, ...])
    - (False, <error>)
    """
    if columns:
        sql_what = ','.join(columns)
    else:
        if name_only:
            sql_what = 'domain.domain'
        else:
            sql_what = 'domain.*'

    sql_where = None
    if disabled_only:
        sql_where = 'domain.active=0'

    try:
        if not conn:
            _wrap = SQLWrap()
            conn = _wrap.conn

        if session.get('is_global_admin'):
            qr = conn.select('domain',
                             what=sql_what,
                             where=sql_where,
                             order='domain ASC')
        else:
            if sql_where:
                sql_where = ' AND ' + sql_where
            qr = conn.select(['domain', 'domain_admins'],
                             vars={'admin': session.username},
                             what=sql_what,
                             where='domain_admins.username=$admin AND domain_admins.domain=domain.domain %s' % sql_where,
                             order='domain.domain ASC')

        if name_only:
            domain_names = [str(r.domain).lower() for r in qr]
            return True, domain_names
        else:
            return True, list(qr)
    except Exception as e:
        return False, repr(e)


@decorators.require_domain_access
def get_all_alias_domains(domain, name_only=False, conn=None):
    if not iredutils.is_domain(domain):
        return False, 'INVALID_DOMAIN_NAME'

    if not conn:
        _wrap = SQLWrap()
        conn = _wrap.conn

    try:
        qr = conn.select('alias_domain',
                         vars={'domain': domain},
                         where='target_domain=$domain')

        if name_only is True:
            target_domains = [str(r.alias_domain).lower()
                              for r in qr
                              if iredutils.is_domain(r.alias_domain)]
            target_domains.sort()

            return True, target_domains
        else:
            return True, list(qr)
    except Exception as e:
        return False, repr(e)


def exclude_not_managed_domains(domains, admin, conn=None):
    """Remove given domains not managed by given admin.

    @domains -- a list/tuple/set of mail domain names
    @admin -- email address of domain admin
    @conn -- sql connection cursor
    """
    if not domains:
        return True, []

    if not iredutils.is_email(admin):
        return False, 'INVALID_ADMIN'

    if admin == session.get('username'):
        if session.get('is_global_admin'):
            return True, domains

    if not conn:
        _wrap = SQLWrap()
        conn = _wrap.conn

    # Get managed domains
    qr = sql_lib_admin.get_managed_domains(conn=conn,
                                           admin=admin,
                                           domain_name_only=True)
    if qr[0]:
        managed_domains = qr[1]
        domains = list(set(domains) & set(managed_domains))
        return True, domains
    else:
        return qr


def enable_disable_domains(domains, action, conn=None):
    """Set account status.

    :param domains: a list/tuple/set of mail domain names
    :param action: enable, disable
    :param conn: sql connection cursor
    """
    qr = exclude_not_managed_domains(domains=domains,
                                     admin=session.get('username'),
                                     conn=conn)
    if qr[0]:
        domains = qr[1]
    else:
        return qr

    action = action.lower()
    if action in ['enable', 'active']:
        active = 1

        # Get pending domains required by ownership verification
        if sql_lib_general.require_domain_ownership_verification(admin=session['username'], conn=conn):
            qr = domain_ownership.get_pending_domains(domains=domains, domain_name_only=True)
            if qr[0]:
                for d in qr[1]:
                    if d in domains:
                        domains.remove(d)

                if not domains:
                    return True,
            else:
                return qr
    else:
        active = 0

    try:
        conn.update('domain',
                    vars={'domains': domains},
                    where='domain IN $domains',
                    active=active)

        if active:
            domain_ownership.remove_pending_domains(domains=domains)

        log_activity(event=action.lower(),
                     msg="{} domain(s): {}.".format(action.title(), ', '.join(domains)))

        return True,
    except Exception as e:
        return False, repr(e)


@decorators.require_domain_access
def __get_sender_bcc_address(domain, conn=None):
    return sql_lib_general.get_bcc_address(account=domain,
                                           account_type='domain',
                                           bcc_type='sender',
                                           conn=conn)


@decorators.require_domain_access
def __get_recipient_bcc_address(domain, conn=None):
    return sql_lib_general.get_bcc_address(account=domain,
                                           account_type='domain',
                                           bcc_type='recipient',
                                           conn=conn)


def __update_domain_bcc(domain,
                        bcc_address=None,
                        bcc_type='sender',
                        remove_all_user_bcc=False,
                        conn=None):
    """Update per-domain sender bcc.

    domain - the domain which needs to update bcc setting
    bcc_address - full email address of bcc destination. bcc setting will be
                  removed if it's None.
    bcc_type - sender (sender bcc), recipient (recipient bcc)
    """
    remove_bcc = False
    if not iredutils.is_email(bcc_address):
        remove_bcc = True

    if bcc_type == 'sender':
        tbl = 'sender_bcc_domain'
        tbl_user = 'sender_bcc_user'
    else:
        tbl = 'recipient_bcc_domain'
        tbl_user = 'recipient_bcc_user'

    if not conn:
        _wrap = SQLWrap()
        conn = _wrap.conn

    sql_vars = {'domain': domain}
    try:
        conn.delete(tbl,
                    vars=sql_vars,
                    where='domain=$domain')

        if not remove_bcc:
            conn.insert(tbl,
                        domain=domain,
                        bcc_address=bcc_address,
                        created=iredutils.get_gmttime(),
                        modified=iredutils.get_gmttime(),
                        active=1)

        if remove_all_user_bcc:
            conn.delete(tbl_user,
                        vars=sql_vars,
                        where='domain=$domain')

        return True,
    except Exception as e:
        return False, repr(e)


def __update_sender_bcc(domain,
                        bcc_address=None,
                        remove_all_user_bcc=False,
                        conn=None):
    return __update_domain_bcc(domain=domain,
                               bcc_address=bcc_address,
                               bcc_type='sender',
                               remove_all_user_bcc=remove_all_user_bcc,
                               conn=conn)


def __update_recipient_bcc(domain, bcc_address=None, remove_all_user_bcc=False, conn=None):
    return __update_domain_bcc(domain=domain,
                               bcc_address=bcc_address,
                               bcc_type='recipient',
                               remove_all_user_bcc=remove_all_user_bcc,
                               conn=conn)


def __get_catchall(domain, conn=None):
    """Get a list of per-domain catch-all addresses.

    :param domain: the domain which needs to update bcc setting
    :param conn: sql connection cursor
    """
    domain = str(domain).lower()
    if not iredutils.is_domain(domain):
        return False, 'INVALID_DOMAIN_NAME'

    if not conn:
        _wrap = SQLWrap()
        conn = _wrap.conn

    try:
        qr = conn.select('forwardings',
                         vars={'domain': domain},
                         what='forwarding',
                         where='address=$domain')

        addresses = []
        for i in qr:
            addr = str(i.forwarding).lower()
            addresses.append(addr)

        addresses.sort()

        return True, addresses
    except Exception as e:
        return False, repr(e)


def __update_catchall(domain, catchall=None, conn=None):
    """Update per-domain catch-all accounts.

    :param domain: the domain which needs to update bcc setting
    :param catchall: a list/tuple/set of email addresses which will receive
                     emails sent to non-existing address under given domain
    :param conn: sql connection cursor
    """
    domain = str(domain).lower()
    if not iredutils.is_domain(domain):
        return False, 'INVALID_DOMAIN_NAME'

    if not conn:
        _wrap = SQLWrap()
        conn = _wrap.conn

    try:
        sql_vars = {'domain': domain}

        # Remove existing one first
        conn.delete('forwardings',
                    vars=sql_vars,
                    where='address=$domain')

        if isinstance(catchall, (tuple, list, set)):
            _addresses = {str(i).lower() for i in catchall if iredutils.is_email(i)}

            # Filter non-existing users in same domain.
            _internal_addrs = {i for i in _addresses if i.endswith('@' + domain)}
            _external_addrs = {i for i in _addresses if not i.endswith('@' + domain)}
            if _internal_addrs:
                _qr = sql_lib_general.filter_existing_emails(mails=_internal_addrs, conn=conn)
                _external_addrs.update(_qr['exist'])
                _addresses = _external_addrs
                del _qr

            del _internal_addrs, _external_addrs

            if _addresses:
                for _addr in _addresses:
                    try:
                        conn.insert('forwardings',
                                    address=domain,
                                    forwarding=_addr,
                                    domain=domain,
                                    dest_domain=_addr.split('@', 1)[-1],
                                    is_list=0,
                                    is_forwarding=0,
                                    is_alias=0,
                                    active=1)
                    except Exception as e:
                        return False, repr(e)

        return True,
    except Exception as e:
        return False, repr(e)


def __get_sender_dependent_relayhost(domain, conn=None):
    """Get per-domain sender dependent relayhost.

    :param domain: the domain which needs to update bcc setting
    :param conn: sql connection cursor
    """
    domain = str(domain).lower()
    if not iredutils.is_domain(domain):
        return False, 'INVALID_DOMAIN_NAME'

    if not conn:
        _wrap = SQLWrap()
        conn = _wrap.conn

    try:
        qr = conn.select('sender_relayhost',
                         vars={'account': '@' + domain},
                         what='relayhost',
                         where='account=$account')

        if qr:
            relayhost = str(qr[0]['relayhost']).lower()
        else:
            relayhost = ''

        return True, relayhost
    except Exception as e:
        return False, repr(e)


def __reset_alias_domains(domain, alias_domains, conn=None):
    """Remove all existing domains and use given domains as new alias domains.

    :param domain: the primary domain
    :param alias_domains: new alias domains. If empty or None, all existing
                          alias domains will be removed.
    :param conn: sql connection cursor
    """
    domain = str(domain).lower()
    if not iredutils.is_domain(domain):
        return False, 'INVALID_DOMAIN_NAME'

    if alias_domains:
        alias_domains = [str(d).lower() for d in alias_domains if iredutils.is_domain(d)]
    else:
        alias_domains = []

    if not conn:
        _wrap = SQLWrap()
        conn = _wrap.conn

    try:
        conn.delete('alias_domain',
                    vars={'domain': domain},
                    where='target_domain=$domain')

        if alias_domains:
            # Remove existing domains
            qr = sql_lib_general.filter_existing_domains(domains=alias_domains, conn=conn)
            alias_domains = qr['nonexist']

        if alias_domains:
            v = []
            for d in alias_domains:
                v += [{'alias_domain': d,
                       'target_domain': domain}]

            conn.multiple_insert('alias_domain', values=v)

        return True,
    except Exception as e:
        return False, repr(e)


def __update_alias_domains(domain,
                           new_alias_domains=None,
                           removed_alias_domains=None,
                           conn=None):
    """Add/remove alias domains.

    :param domain: the primary domain
    :param new_alias_domains: add new alias domains.
    :param removed_alias_domains: remove existing alias domains.
    :param conn: sql connection cursor
    """
    domain = str(domain).lower()
    if not iredutils.is_domain(domain):
        return False, 'INVALID_DOMAIN_NAME'

    if new_alias_domains:
        new_alias_domains = [str(d).lower()
                             for d in new_alias_domains
                             if iredutils.is_domain(d)]
    else:
        new_alias_domains = []

    if removed_alias_domains:
        removed_alias_domains = [str(d).lower()
                                 for d in removed_alias_domains
                                 if iredutils.is_domain(d)]
    else:
        removed_alias_domains = []

    if not conn:
        _wrap = SQLWrap()
        conn = _wrap.conn

    sql_vars = {
        'domain': domain,
        'removed_alias_domains': removed_alias_domains,
    }

    try:
        if removed_alias_domains:
            conn.delete('alias_domain',
                        vars=sql_vars,
                        where='target_domain=$domain AND alias_domain IN $removed_alias_domains')

        if new_alias_domains:
            # Remove existing domains
            qr = sql_lib_general.filter_existing_domains(domains=new_alias_domains, conn=conn)
            new_alias_domains = qr['nonexist']

        if new_alias_domains:
            for d in new_alias_domains:
                try:
                    conn.insert('alias_domain',
                                alias_domain=d,
                                target_domain=domain)
                except:
                    pass

        return True,
    except Exception as e:
        return False, repr(e)


# Get used quota of domains.
def get_domain_used_quota(conn, domains=None):
    used_quota = {}

    if not domains:
        return used_quota

    domains = [str(d).lower() for d in domains if iredutils.is_domain(d)]
    try:
        qr = conn.select(
            settings.SQL_TBL_USED_QUOTA,
            vars={'domains': domains},
            where='domain IN $domains',
            what='domain,SUM(bytes) AS size, SUM(messages) AS messages',
            group='domain',
            order='domain',
        )

        for r in qr:
            used_quota[str(r.domain)] = {'size': r.size, 'messages': r.messages}
    except:
        pass

    return used_quota


def get_allocated_domain_quota(domains, conn=None):
    num = 0

    if not isinstance(domains, (list, set, tuple)):
        return num

    if len(domains) == 0:
        return num

    if not conn:
        _wrap = SQLWrap()
        conn = _wrap.conn

    try:
        qr = conn.select('mailbox',
                         vars={'domains': domains},
                         what='SUM(quota) AS total',
                         where='domain IN $domains')

        if qr:
            num = int(qr[0].total) or 0
    except:
        pass

    return num


def delete_domains(domains,
                   keep_mailbox_days=0,
                   conn=None):
    domains = [str(d).lower() for d in domains if iredutils.is_domain(d)]
    if not domains:
        return True,

    if not conn:
        _wrap = SQLWrap()
        conn = _wrap.conn

    qr = exclude_not_managed_domains(domains=domains,
                                     admin=session.get('username'),
                                     conn=conn)
    if qr[0]:
        domains = qr[1]
        if not domains:
            return True,
    else:
        return qr

    try:
        keep_mailbox_days = abs(int(keep_mailbox_days))
    except:
        keep_mailbox_days = 0

    if not session.get('is_global_admin'):
        _max_days = max(settings.DAYS_TO_KEEP_REMOVED_MAILBOX)
        if keep_mailbox_days > _max_days:
            # Get the max days
            keep_mailbox_days = _max_days

    # Keep mailboxes 'forever', set to 100 years.
    if keep_mailbox_days == 0:
        sql_keep_days = web.sqlliteral('Null')
    else:
        if settings.backend == 'pgsql':
            sql_keep_days = web.sqlliteral("""CURRENT_TIMESTAMP + INTERVAL '%d DAYS'""" % keep_mailbox_days)
        else:
            # settings.backend == 'mysql'
            sql_keep_days = web.sqlliteral('DATE_ADD(CURDATE(), INTERVAL %d DAY)' % keep_mailbox_days)

    sql_vars = {
        'domains': domains,
        'admin': session.get('username'),
        'sql_keep_days': sql_keep_days,
    }

    # Log maildir paths of existing users
    try:
        if settings.backend == 'pgsql':
            sql_raw = '''
                INSERT INTO deleted_mailboxes (username, maildir, domain, admin, delete_date)
                SELECT username, \
                       storagebasedirectory || '/' || storagenode || '/' || maildir, \
                       domain, \
                       $admin, \
                       $sql_keep_days
                  FROM mailbox
                 WHERE domain IN $domains'''
        else:
            # settings.backend == 'mysql'
            sql_raw = '''
                INSERT INTO deleted_mailboxes (username, maildir, domain, admin, delete_date)
                SELECT username, \
                       CONCAT(storagebasedirectory, '/', storagenode, '/', maildir) AS maildir, \
                       domain, \
                       $admin, \
                       $sql_keep_days
                  FROM mailbox
                 WHERE domain IN $domains'''

        conn.query(sql_raw, vars=sql_vars)
    except Exception as e:
        logger.error(e)

    try:
        # Delete domain name
        for tbl in ['domain', 'alias', 'domain_admins', 'mailbox',
                    'recipient_bcc_domain', 'recipient_bcc_user',
                    'sender_bcc_domain', 'sender_bcc_user',
                    'forwardings', 'moderators',
                    settings.SQL_TBL_USED_QUOTA]:
            conn.delete(tbl,
                        vars=sql_vars,
                        where='domain IN $domains')

        # Delete alias domain
        conn.delete('alias_domain',
                    vars=sql_vars,
                    where='alias_domain IN $domains OR target_domain IN $domains')

        # Delete domain admins
        for d in domains:
            conn.delete('domain_admins',
                        vars={'domain': '%%@' + d},
                        where='username LIKE $domain')
    except Exception as e:
        return False, repr(e)

    # Delete domains in Amavisd database: users, policy.
    if settings.amavisd_enable_policy_lookup:
        pdomains = ['@' + d for d in domains]
        delete_policy_accounts(accounts=pdomains)

    # Delete from `iredadmin.domain_ownership`
    domain_ownership.remove_pending_domains(domains=domains)

    # Delete throttling & greylisting settings.
    if settings.iredapd_enabled:
        iredapd_utils.delete_settings_for_removed_domains(domains=domains)

    for d in domains:
        log_activity(event='delete',
                     domain=d,
                     msg="Delete domain: %s." % d)

    return True,


@decorators.require_domain_access
def simple_profile(domain, columns=None, conn=None):
    if not iredutils.is_domain(domain):
        return False, 'INVALID_DOMAIN_NAME'

    sql_what = '*'
    if columns:
        sql_what = ','.join(columns)

    try:
        if not conn:
            _wrap = SQLWrap()
            conn = _wrap.conn

        qr = conn.select('domain',
                         vars={'domain': domain},
                         what=sql_what,
                         where='domain=$domain',
                         limit=1)
        if qr:
            p = list(qr)[0]
            return True, p
        else:
            return False, 'INVALID_DOMAIN_NAME'
    except Exception as e:
        return False, repr(e)


@decorators.require_domain_access
def profile(domain, conn=None):
    domain = str(domain).lower()

    if not iredutils.is_domain(domain):
        return False, 'INVALID_DOMAIN_NAME'

    if not conn:
        _wrap = SQLWrap()
        conn = _wrap.conn

    try:
        # Get domain profile first.
        _qr = simple_profile(domain=domain, conn=conn)
        if _qr[0]:
            _profile = _qr[1]
        else:
            return _qr

        # Get BCC addresses
        _profile['sbcc_addr'] = ''
        _profile['rbcc_addr'] = ''
        _qr = __get_sender_bcc_address(domain=domain, conn=conn)
        if _qr[0]:
            _profile['sbcc_addr'] = _qr[1]
        else:
            return _qr

        _qr = __get_recipient_bcc_address(domain=domain, conn=conn)
        if _qr[0]:
            _profile['rbcc_addr'] = _qr[1]
        else:
            return _qr

        # catchall: per-domain catch-all addresses
        _profile['catchall'] = []
        _qr = __get_catchall(domain=domain, conn=conn)
        if _qr[0]:
            _profile['catchall'] = _qr[1]
        else:
            return _qr

        # relayhost (sender_relayhost.relayhost)
        _profile['relayhost'] = ''
        _qr = __get_sender_dependent_relayhost(domain=domain, conn=conn)
        if _qr[0]:
            _profile['relayhost'] = _qr[1]
        else:
            return _qr

        # num_existing_users
        _profile['num_existing_users'] = sql_lib_general.num_users_under_domain(domain=domain, conn=conn)

        return True, _profile
    except Exception as e:
        return False, repr(e)


# Do not apply @decorators.require_domain_access
def get_domain_enabled_services(domain, conn=None):
    qr = sql_lib_general.get_domain_settings(domain=domain, conn=conn)
    if qr[0]:
        domain_settings = qr[1]
        enabled_services = domain_settings.get('enabled_services', [])
        return True, enabled_services
    else:
        return qr


def add(form, conn=None):
    domain = form_utils.get_domain_name(form)

    # Check domain name.
    if not iredutils.is_domain(domain):
        return False, 'INVALID_DOMAIN_NAME'

    if not conn:
        _wrap = SQLWrap()
        conn = _wrap.conn

    # Check whether domain name already exist (domainName, domainAliasName).
    if sql_lib_general.is_domain_exists(domain=domain, conn=conn):
        return False, 'ALREADY_EXISTS'

    params = {
        'domain': domain,
        'mailboxes': 0,
        'aliases': 0,
        'disclaimer': '',
        'created': iredutils.get_gmttime(),
    }

    # Quota
    domain_quota = form_utils.get_domain_quota_and_unit(form=form)['quota']
    params['maxquota'] = domain_quota

    # Number of users
    kv = form_utils.get_form_dict(form=form,
                                  input_name='numberOfUsers',
                                  key_name='mailboxes',
                                  default_value=0,
                                  is_integer=True)
    params.update(kv)

    # Number of aliases
    kv = form_utils.get_form_dict(form=form,
                                  input_name='numberOfAliases',
                                  key_name='aliases',
                                  default_value=0,
                                  is_integer=True)
    params.update(kv)

    # Number of mailing lists
    kv = form_utils.get_form_dict(form=form,
                                  input_name='numberOfLists',
                                  key_name='maillists',
                                  default_value=0,
                                  is_integer=True)
    params.update(kv)

    # Name
    kv = form_utils.get_form_dict(form=form, input_name='cn', key_name='description')
    params.update(kv)

    # Transport
    kv = form_utils.get_form_dict(form=form,
                                  input_name='transport',
                                  default_value=settings.default_mta_transport,
                                  to_string=True)
    params.update(kv)

    #
    # Update domain account settings
    #
    domain_settings = {}
    kv = form_utils.get_form_dict(form=form,
                                  input_name='preferredLanguage',
                                  key_name='default_language',
                                  to_string=True)
    domain_settings.update(kv)

    kv = form_utils.get_form_dict(form=form,
                                  input_name='defaultQuota',
                                  key_name='default_user_quota',
                                  to_string=True)
    domain_settings.update(kv)

    _quota = form_utils.get_single_value(form=form,
                                         input_name='maxUserQuota',
                                         is_integer=True,
                                         default_value=0)
    if _quota:
        _unit = form_utils.get_single_value(form=form,
                                            input_name='maxUserQuotaUnit',
                                            to_string=True)

        if _unit == 'GB':
            _quota = _quota * 1024
        elif _unit == 'TB':
            _quota = _quota * 1024 * 1024

        domain_settings.update({'max_user_quota': _quota})

    kv = form_utils.get_form_dict(form=form,
                                  input_name='timezone',
                                  to_string=True)
    if 'none' in list(kv.values()):
        pass
    else:
        domain_settings.update(kv)

    # for normal domain admin: check domain creation limitations
    qr = sql_lib_admin.get_per_admin_domain_creation_limits(admin=session.get('username'), conn=conn)
    if qr['error_code']:
        return False, repr(qr['error_code'])
    else:
        # Update number of quota, users, aliases
        _l = [('num_max_quota', 'num_spare_quota', 'maxquota'),
              ('num_max_users', 'num_spare_users', 'mailboxes'),
              ('num_max_aliases', 'num_spare_aliases', 'aliases'),
              ('num_max_lists', 'num_spare_lists', 'maillists')]

        for (_limit_max, _limit_spare, _key) in _l:
            if qr[_limit_max] > 0:
                _form_num = params.get(_key, 0)
                _num_spare = qr[_limit_spare]

                if _form_num == 0:
                    params[_key] = _num_spare
                else:
                    if _form_num >= _num_spare:
                        params[_key] = _num_spare

        # max user quota
        _max_user_quota = domain_settings.get('max_user_quota', 0)
        if _max_user_quota > 0:
            if qr['num_max_quota'] > 0:
                if _max_user_quota >= qr['num_max_quota']:
                    domain_settings['max_user_quota'] = qr['num_max_quota']

    if settings.ADDITIONAL_DISABLED_DOMAIN_SERVICES:
        params['disabled_mail_services'] = settings.ADDITIONAL_DISABLED_DOMAIN_SERVICES

    params['settings'] = sqlutils.account_settings_dict_to_string(domain_settings)

    # Domain ownership verification is required if it was added by a normal
    # domain admin. And we cannot activate this domain immediately.
    params['active'] = 1
    if sql_lib_general.require_domain_ownership_verification(admin=session['username'], conn=conn):
        qr = domain_ownership.get_verified_domains(domains=[domain], conn=None)
        if qr[0]:
            _verified_domains = qr[1]
            if domain in _verified_domains:
                params['active'] = 1
            else:
                params['active'] = 0
        else:
            return qr

    # Add domain in database.
    try:
        # Domain ownership verification required
        if sql_lib_general.require_domain_ownership_verification(admin=session['username'], conn=conn):
            qr = domain_ownership.set_verify_code_for_new_domains(primary_domain=domain)
            if not qr[0]:
                return qr

        conn.insert('domain', **params)

        log_activity(msg="New domain: %s." % domain,
                     domain=domain,
                     event='create')

        # If it's a normal domain admin with permission to create new domain,
        # assign current admin as admin of this newly created domain.
        if session.get('create_new_domains'):
            qr = assign_admins_to_domain(domain=domain,
                                         admins=[session.get('username')],
                                         conn=conn)
            if not qr[0]:
                return qr

    except Exception as e:
        return False, repr(e)

    return True,


@decorators.require_domain_access
def update(domain, profile_type, form, conn=None):
    profile_type = str(profile_type)
    domain = str(domain).lower()
    sql_vars = {'domain': domain}

    if not conn:
        _wrap = SQLWrap()
        conn = _wrap.conn

    db_settings = iredutils.get_settings_from_db()

    # Get current domain profile
    qr = simple_profile(conn=conn, domain=domain)
    if qr[0]:
        domain_profile = qr[1]
        domain_settings = sqlutils.account_settings_string_to_dict(domain_profile.get('settings', ''))
        del qr
    else:
        return qr

    # Check disabled domain profiles
    disabled_domain_profiles = []
    if not session.get('is_global_admin'):
        disabled_domain_profiles = domain_settings.get('disabled_domain_profiles', [])
        if profile_type in disabled_domain_profiles:
            return False, 'PERMISSION_DENIED'

    # Pre-defined update key:value.
    updates = {'modified': iredutils.get_gmttime()}

    if profile_type == 'general':
        # Get name
        cn = form.get('cn', '')
        updates['description'] = cn

        # Get account status
        if not domain_ownership.is_pending_domain(domain=domain):
            updates['active'] = 0
            if 'accountStatus' in form:
                updates['active'] = 1

        domain_quota = int(domain_profile.get('maxquota', 0))

        if session.get('is_global_admin') or session.get('create_new_domains'):
            # Get domain quota size.
            qr = form_utils.get_domain_quota_and_unit(form=form)
            domain_quota = qr['quota']

            qr = assign_given_domain_quota(domain=domain,
                                           quota=domain_quota,
                                           domain_profile=domain_profile,
                                           conn=conn)
            if qr[0]:
                domain_quota = qr[1]
            else:
                return qr

            updates['maxquota'] = domain_quota

        # Get max user quota
        if session.get('is_global_admin'):
            max_user_quota = str(form.get('maxUserQuota', '0'))
            if max_user_quota.isdigit():
                max_user_quota = int(max_user_quota)
            else:
                max_user_quota = 0

            if max_user_quota >= 0:
                max_user_quota_unit = str(form.get('maxUserQuotaUnit', 'MB'))
                if max_user_quota_unit == 'GB':
                    max_user_quota = max_user_quota * 1024
                elif max_user_quota_unit == 'TB':
                    max_user_quota = max_user_quota * 1024 * 1024

                if domain_quota > 0:
                    if max_user_quota <= domain_quota:
                        domain_settings['max_user_quota'] = max_user_quota
                    else:
                        domain_settings['max_user_quota'] = domain_quota
                else:
                    domain_settings['max_user_quota'] = max_user_quota

        # Get default quota for new user.
        default_user_quota = form_utils.get_single_value(form=form,
                                                         input_name='defaultQuota',
                                                         default_value=0,
                                                         is_integer=True)
        if default_user_quota > 0:
            domain_settings['default_user_quota'] = default_user_quota
        else:
            if 'default_user_quota' in domain_settings:
                domain_settings.pop('default_user_quota')

        # re-update `default_user_quota`
        _max = domain_settings.get('max_user_quota', 0)
        _default = domain_settings.get('default_user_quota', 0)
        if _max and _default:
            if _default > _max:
                domain_settings['default_user_quota'] = _max

    elif profile_type == 'bcc':
        # BCC must handle alias domains.
        # Get all alias domains.
        bcc_alias_domains = [domain]
        qr = get_all_alias_domains(domain=domain,
                                   name_only=True,
                                   conn=conn)
        if qr[0]:
            bcc_alias_domains += qr[1]

        # Delete old records first.
        try:
            for d in bcc_alias_domains:
                _sql_vars = {'domain': d}

                conn.delete('sender_bcc_domain', vars=_sql_vars, where='domain=$domain')
                conn.delete('recipient_bcc_domain', vars=_sql_vars, where='domain=$domain')
        except Exception as e:
            return False, repr(e)

        sbcc = str(form.get('senderBccAddress', None))
        rbcc = str(form.get('recipientBccAddress', None))

        if iredutils.is_email(sbcc):
            address_domain = sbcc.split('@', -1)[-1]
            if sql_lib_general.is_domain_exists(domain=address_domain, conn=conn):
                # Is a hosted local domain
                if not sql_lib_general.is_email_exists(mail=sbcc, conn=conn):
                    sbcc = None

            if sbcc:
                for d in bcc_alias_domains:
                    try:
                        # Add domain bcc
                        conn.insert('sender_bcc_domain',
                                    domain=d,
                                    bcc_address=sbcc,
                                    created=iredutils.get_gmttime(),
                                    modified=iredutils.get_gmttime(),
                                    active=1)
                    except Exception as e:
                        return False, repr(e)

        if iredutils.is_email(rbcc):
            address_domain = rbcc.split('@', -1)[-1]
            if sql_lib_general.is_domain_exists(domain=address_domain, conn=conn):
                # Is a hosted internal domain
                if not sql_lib_general.is_email_exists(mail=rbcc, conn=conn):
                    rbcc = None

            if rbcc:
                for d in bcc_alias_domains:
                    try:
                        conn.insert('recipient_bcc_domain',
                                    domain=d,
                                    bcc_address=rbcc,
                                    created=iredutils.get_gmttime(),
                                    modified=iredutils.get_gmttime(),
                                    active=1)
                    except Exception as e:
                        return False, repr(e)

    elif profile_type == 'relay':
        new_transport = str(form.get('mtaTransport', settings.default_mta_transport))
        updates['transport'] = new_transport

        if 'relay_without_verify_local_recipient' in form:
            if new_transport.startswith(('smtp:', 'uucp:', ':')):
                updates['backupmx'] = 1
        else:
            updates['backupmx'] = 0

        # Get sender dependent relayhost
        relayhost = str(form.get('relayhost', ''))

        # Update relayhost
        _qr = sql_lib_general.update_sender_relayhost(account='@' + domain,
                                                      relayhost=relayhost,
                                                      conn=conn)
        if not _qr[0]:
            return _qr

    elif profile_type == 'catchall':
        # Get list of destination addresses.
        _addresses = {str(v).lower()
                      for v in form.get('catchall_addresses', '').splitlines()
                      if iredutils.is_email(v)}

        _qr = __update_catchall(domain=domain,
                                catchall=_addresses,
                                conn=conn)
        if not _qr[0]:
            return _qr

    elif profile_type == 'aliases':
        # Get old alias domains
        old_alias_domains = []
        qr = get_all_alias_domains(domain=domain,
                                   name_only=True,
                                   conn=conn)
        if qr[0]:
            old_alias_domains = qr[1]

        # Delete old records first.
        try:
            conn.delete('alias_domain',
                        vars=sql_vars,
                        where='target_domain=$domain')
        except Exception as e:
            return False, repr(e)

        # Get domain aliases from web form and store in LDAP.
        all_alias_domains = {str(d).lower()
                             for d in form.get('domainAliasName', [])
                             if d != domain and not sql_lib_general.is_domain_exists(domain=d, conn=conn)}

        removed_alias_domains = [d for d in old_alias_domains if d not in all_alias_domains]
        if removed_alias_domains:
            for d in removed_alias_domains:
                # Delete all records in bcc tables.
                d_in_sql = web.sqlquote(d)
                conn.delete('sender_bcc_domain', where='domain=%s' % d_in_sql)
                conn.delete('recipient_bcc_domain', where='domain=%s' % d_in_sql)
                conn.delete('sender_bcc_user', where='domain=%s' % d_in_sql)
                conn.delete('recipient_bcc_user', where='domain=%s' % d_in_sql)

            # Remove pending domain ownership verification
            domain_ownership.remove_pending_domains(domains=removed_alias_domains)

        if all_alias_domains:
            v = []
            qr = domain_ownership.get_pending_domains(domains=all_alias_domains,
                                                      domain_name_only=True)
            if qr[0]:
                _pending_domains = qr[1]
            else:
                return qr

            for ad in all_alias_domains:
                _record = {
                    'alias_domain': ad,
                    'target_domain': domain,
                    'created': iredutils.get_gmttime(),
                    'active': 1,
                }

                # Require domain ownership verification
                _new_alias_domains = []
                if ad in _pending_domains:
                    # Existing pending domain
                    if not session.get('is_global_admin'):
                        _record['active'] = 0
                else:
                    # New domain
                    if ad not in old_alias_domains:
                        _new_alias_domains.append(ad)

                        if not session.get('is_global_admin'):
                            _record['active'] = 0

                v += [_record]

                # Add verify codes for new domain
                if _new_alias_domains:
                    if not session.get('is_global_admin'):
                        domain_ownership.set_verify_code_for_new_domains(primary_domain=domain,
                                                                         alias_domains=_new_alias_domains)

            # Add alis domains.
            if v:
                try:
                    conn.multiple_insert('alias_domain', values=v)
                    log_activity(msg="Update alias domains of {} to: {}.".format(domain, ', '.join(all_alias_domains)),
                                 domain=domain,
                                 event='update')

                except Exception as e:
                    return False, repr(e)

            # Update bcc records for existing accounts
            try:
                # Domain bcc
                for domain_bcc_table in ['sender_bcc_domain', 'recipient_bcc_domain']:
                    # Get all bcc records of mail users, then add same bcc for alias domains
                    qr = conn.select(domain_bcc_table,
                                     vars=sql_vars,
                                     what='domain,bcc_address,active',
                                     where='domain=$domain')

                    new_bcc_records = []
                    for ad in all_alias_domains:
                        for r in qr:
                            new_bcc_records += [{
                                'bcc_address': r.bcc_address,
                                'active': r.active,
                                'domain': ad,
                                'created': iredutils.get_gmttime(),
                            }]

                    if new_bcc_records:
                        conn.multiple_insert(domain_bcc_table, values=new_bcc_records)
                        del new_bcc_records

                # User bcc
                for user_bcc_table in ['sender_bcc_user', 'recipient_bcc_user']:
                    qr = conn.select(user_bcc_table,
                                     vars=sql_vars,
                                     what='username,bcc_address,active',
                                     where='domain=$domain')

                    new_bcc_records = []
                    for ad in all_alias_domains:
                        for r in qr:
                            new_bcc_records += [{
                                'username': r.username.split('@', 1)[0] + '@' + ad,
                                'bcc_address': r.bcc_address,
                                'active': r.active,
                                'domain': ad,
                                'created': iredutils.get_gmttime(),
                            }]

                    if new_bcc_records:
                        conn.multiple_insert(user_bcc_table, values=new_bcc_records)
                        del new_bcc_records
            except:
                pass

    elif profile_type == 'wblist':
        if session.get('is_global_admin') or 'wblist' not in disabled_domain_profiles:
            if settings.amavisd_enable_policy_lookup:
                wl_senders = get_wblist_from_form(form, 'wl_sender')
                bl_senders = get_wblist_from_form(form, 'bl_sender')
                wl_rcpts = get_wblist_from_form(form, 'wl_rcpt')
                bl_rcpts = get_wblist_from_form(form, 'bl_rcpt')

                qr = lib_wblist.add_wblist(account='@' + domain,
                                           wl_senders=wl_senders,
                                           bl_senders=bl_senders,
                                           wl_rcpts=wl_rcpts,
                                           bl_rcpts=bl_rcpts,
                                           flush_before_import=True)
                return qr

    elif profile_type == 'throttle':
        if settings.iredapd_enabled:
            t_account = '@' + domain

            inbound_setting = form_utils.get_throttle_setting(form, account=t_account, inout_type='inbound')
            outbound_setting = form_utils.get_throttle_setting(form, account=t_account, inout_type='outbound')

            iredapd_throttle.add_throttle(account=t_account,
                                          setting=inbound_setting,
                                          inout_type='inbound')

            iredapd_throttle.add_throttle(account=t_account,
                                          setting=outbound_setting,
                                          inout_type='outbound')

    elif profile_type == 'greylisting':
        if settings.iredapd_enabled:
            qr = iredapd_greylist.update_greylist_settings_from_form(account='@' + domain, form=form)
            return qr

    elif profile_type == 'advanced':
        # Update min/max password length in domain setting
        if session.get('is_global_admin') or ('password_policies' not in disabled_domain_profiles):
            for (_input_name, _key_name) in [('minPasswordLength', 'min_passwd_length'),
                                             ('maxPasswordLength', 'max_passwd_length')]:
                try:
                    _length = int(form.get(_input_name, 0))
                except:
                    _length = 0

                if _length > 0:
                    if not session.get('is_global_admin'):
                        # Make sure domain setting doesn't exceed global setting.
                        if _input_name == 'minPasswordLength':
                            # Cannot be shorter than global setting.
                            if _length < db_settings['min_passwd_length']:
                                _length = db_settings['min_passwd_length']
                        elif _input_name == 'maxPasswordLength':
                            # Cannot be longer than global setting.
                            if (db_settings['max_passwd_length'] > 0) and \
                               (_length > db_settings['max_passwd_length'] or _length <= db_settings['min_passwd_length']):
                                _length = db_settings['max_passwd_length']

                    domain_settings[_key_name] = _length
                else:
                    if _key_name in domain_settings:
                        domain_settings.pop(_key_name)

        # Update default mailing lists of newly created mail user
        default_mailing_lists = [str(v).lower()
                                 for v in form.get('default_mail_list', [])
                                 if iredutils.is_email(v)]

        if default_mailing_lists:
            domain_settings['default_mailing_lists'] = default_mailing_lists
        else:
            if 'default_mailing_lists' in domain_settings:
                domain_settings.pop('default_mailing_lists')

        # Update default groups of newly created mail user
        default_groups = [str(v).lower()
                          for v in form.get('defaultList', [])
                          if iredutils.is_email(v)]

        if default_groups:
            domain_settings['default_groups'] = default_groups
        else:
            if 'default_groups' in domain_settings:
                domain_settings.pop('default_groups')

        # Update default language for new user
        default_language = form_utils.get_language(form)
        if default_language in iredutils.get_language_maps():
            domain_settings['default_language'] = default_language

        domain_settings['timezone'] = form_utils.get_timezone(form)

        # Default per-user bcc address
        if session.get('is_global_admin') or 'bcc' not in disabled_domain_profiles:
            rbcc = web.safestr(form.get('recipientBccAddress', ''))
            sbcc = web.safestr(form.get('senderBccAddress', ''))

            for (addr, name) in [(rbcc, 'default_recipient_bcc'), (sbcc, 'default_sender_bcc')]:
                if name in domain_settings:
                    domain_settings.pop(name)

                if iredutils.is_email(addr):
                    rbcc_domain = addr.split('@', 1)[-1]
                    # Verify existence before saving
                    if sql_lib_general.is_domain_exists(domain=rbcc_domain, conn=conn):
                        if sql_lib_general.is_email_exists(mail=addr, conn=conn):
                            domain_settings[name] = addr
                    else:
                        domain_settings[name] = addr

        # Get enabled_services.
        if form.get('enabledService', []):
            domain_settings['enabled_services'] = [str(v).lower() for v in form.get('enabledService', [])]
        else:
            if 'enabled_services' in domain_settings:
                domain_settings.pop('enabled_services')

        # Get disabled services
        if session.get('is_global_admin') or \
           ('disabled_mail_services' not in disabled_domain_profiles):
            form_disabled_mail_services = [str(v).lower()
                                           for v in form.get('disabledMailService', [])
                                           if v in AVAILABLE_DOMAIN_DISABLED_MAIL_SERVICES]

            if form_disabled_mail_services:
                domain_settings['disabled_mail_services'] = form_disabled_mail_services
            else:
                if 'disabled_mail_services' in domain_settings:
                    domain_settings.pop('disabled_mail_services')

            # Update disabled_mail_services for all existing mail users.
            if 'disable_services_for_existing_users' in form:
                _disabled_mail_services = [v for v in form_disabled_mail_services]
                _enabled_services = [v for v in AVAILABLE_DOMAIN_DISABLED_MAIL_SERVICES
                                     if v not in _disabled_mail_services]

                _update_services = {}
                for srv in _disabled_mail_services:
                    _update_services['enable' + srv] = 0

                for srv in _enabled_services:
                    _update_services['enable' + srv] = 1

                # Update all mail users.
                if _update_services:
                    try:
                        conn.update('mailbox',
                                    vars={'domain': domain},
                                    where='domain=$domain',
                                    **_update_services)
                    except Exception as e:
                        return False, repr(e)

                del form_disabled_mail_services
                del _disabled_mail_services, _enabled_services, _update_services

        # Get disabled user preferences.
        if form.get('disabledUserPreference', []):
            domain_settings['disabled_user_preferences'] = [str(v).lower() for v in form.get('disabledUserPreference', [])]
        else:
            if 'disabled_user_preferences' in domain_settings:
                domain_settings.pop('disabled_user_preferences')

        if session.get('is_global_admin') or session.get('create_new_domains'):
            try:
                num_users = int(form.get('numberOfUsers', 0))
            except:
                num_users = 0

            try:
                num_aliases = int(form.get('numberOfAliases', 0))
            except:
                num_aliases = 0

            try:
                num_lists = int(form.get('numberOfLists', 0))
            except:
                num_lists = 0

            if session.get('is_global_admin'):
                updates['mailboxes'] = num_users
                updates['aliases'] = num_aliases
                updates['maillists'] = num_lists
            else:
                # Get per-admin settings used by normal admin to create new domains.
                qr = sql_lib_general.get_admin_settings(admin=session.get('username'),
                                                        existing_settings=None,
                                                        conn=conn)
                if qr[0]:
                    admin_settings = qr[1]
                    num_max_users = admin_settings.get('create_max_users', 0)
                    num_max_aliases = admin_settings.get('create_max_aliases', 0)
                    num_max_lists = admin_settings.get('create_max_lists', 0)

                    if num_max_users:
                        # managed users in all managed domains
                        num_managed_users = sql_lib_admin.num_managed_users(admin=session.get('username'),
                                                                            listed_only=True,
                                                                            conn=conn)

                        # managed users in current domain
                        num_existing_users = sql_lib_admin.num_managed_users(admin=session.get('username'),
                                                                             domains=[domain],
                                                                             listed_only=True,
                                                                             conn=conn)

                        # max number allowed to set
                        num_spare_users = num_max_users - (num_managed_users - num_existing_users)
                        if num_users <= num_spare_users:
                            updates['mailboxes'] = num_users
                        else:
                            updates['mailboxes'] = num_spare_users
                    else:
                        updates['mailboxes'] = num_users

                    if num_max_aliases:
                        # managed aliases in all managed domains
                        num_managed_aliases = sql_lib_admin.num_managed_aliases(admin=session.get('username'),
                                                                                listed_only=True,
                                                                                conn=conn)

                        # managed aliases in current domain
                        num_existing_aliases = sql_lib_admin.num_managed_aliases(admin=session.get('username'),
                                                                                 domains=[domain],
                                                                                 listed_only=True,
                                                                                 conn=conn)

                        num_spare_aliases = num_max_aliases - (num_managed_aliases - num_existing_aliases)
                        if num_aliases <= num_spare_aliases:
                            updates['aliases'] = num_aliases
                        else:
                            updates['aliases'] = num_spare_aliases
                    else:
                        updates['aliases'] = num_aliases

                    if num_max_lists:
                        num_managed_lists = sql_lib_admin.num_managed_lists(admin=session.get('username'),
                                                                            listed_only=True,
                                                                            conn=conn)

                        num_existing_lists = sql_lib_admin.num_managed_lists(admin=session.get('username'),
                                                                             domains=[domain],
                                                                             listed_only=True,
                                                                             conn=conn)

                        num_spare_lists = num_max_lists - (num_managed_lists - num_existing_lists)
                        if num_lists <= num_spare_lists:
                            updates['maillists'] = num_lists
                        else:
                            updates['maillists'] = num_spare_lists
                    else:
                        updates['maillists'] = num_lists

        if session.get('is_global_admin'):
            # Get disabled domain profiles.
            if form.get('disabledDomainProfile', []):
                domain_settings['disabled_domain_profiles'] = [str(v).lower() for v in form.get('disabledDomainProfile', [])]
            else:
                if 'disabled_domain_profiles' in domain_settings:
                    domain_settings.pop('disabled_domain_profiles')

            # Get disabled user profiles.
            if form.get('disabledUserProfile', []):
                domain_settings['disabled_user_profiles'] = [str(v).lower() for v in form.get('disabledUserProfile', [])]
            else:
                if 'disabled_user_profiles' in domain_settings:
                    domain_settings.pop('disabled_user_profiles')
    elif profile_type == 'backupmx':
        is_backupmx = ('backupmx' in form)

        if is_backupmx:
            updates['backupmx'] = 1

            primary_mx = form_utils.get_single_value(form,
                                                     input_name='primary_mx',
                                                     to_string=True)
            if primary_mx:
                updates['transport'] = 'relay:%s' % primary_mx
            else:
                # Let postfix query DNS records to get primary mx.
                updates['transport'] = 'relay:%s' % domain
        else:
            updates['backupmx'] = 0
            updates['transport'] = settings.default_mta_transport

    updates['settings'] = sqlutils.account_settings_dict_to_string(domain_settings)
    try:
        conn.update('domain',
                    vars=sql_vars,
                    where='domain=$domain',
                    **updates)

        log_activity(msg="Update domain profile: {} ({}).".format(domain, profile_type),
                     domain=domain,
                     event='update')

        return True,
    except Exception as e:
        return False, repr(e)


def get_paged_domains(first_char=None,
                      cur_page=1,
                      disabled_only=False,
                      conn=None):
    admin = session.get('username')
    page = int(cur_page) or 1

    # A dict used to store domain profiles.
    # Format: {'<domain>': {<key>: <value>, <key>: <value>, ...}}
    records = {}

    try:
        sql_where = ''

        if session.get('is_global_admin'):
            if first_char:
                sql_where = """ domain LIKE %s""" % web.sqlquote(first_char.lower() + '%')

            if disabled_only:
                if sql_where:
                    sql_where += ' AND active=0'
                else:
                    sql_where += ' active=0'

            if not sql_where:
                sql_where = None

            sql_what = 'domain, description, transport, backupmx, active, aliases, mailboxes, maillists, maxquota, quota'
            qr = conn.select('domain',
                             what=sql_what,
                             where=sql_where,
                             limit=settings.PAGE_SIZE_LIMIT,
                             order='domain',
                             offset=(page - 1) * settings.PAGE_SIZE_LIMIT)

        else:
            sql_where = ' domain.domain = domain_admins.domain AND domain_admins.username = %s' % web.sqlquote(admin)

            if first_char:
                sql_where += """ AND domain.domain LIKE %s""" % web.sqlquote(first_char.lower() + '%')

            if disabled_only:
                if sql_where:
                    sql_where += ' AND domain.active=0'
                else:
                    sql_where += 'domain.active=0'

            sql_what = 'domain.domain, domain.description, domain.transport,'
            sql_what += 'domain.backupmx, domain.active, domain.aliases,'
            sql_what += 'domain.mailboxes, domain.maillists, domain.maxquota,'
            sql_what += 'domain.quota'
            qr = conn.select(['domain', 'domain_admins'],
                             what=sql_what,
                             where=sql_where,
                             limit=settings.PAGE_SIZE_LIMIT,
                             order='domain.domain',
                             offset=(page - 1) * settings.PAGE_SIZE_LIMIT)

        if not qr:
            return True, {}

        for i in qr:
            _domain = str(i.domain).lower()
            records[_domain] = i

        sql_vars = {'domains': list(records.keys())}

        # Get num_existing_users
        qr = conn.select('mailbox',
                         vars=sql_vars,
                         what='domain, SUM(mailbox.quota) AS quota_count, COUNT(username) AS total',
                         where='domain IN $domains',
                         group='domain',
                         limit=settings.PAGE_SIZE_LIMIT)

        for i in qr:
            _domain = str(i.domain).lower()
            records[_domain]['num_existing_users'] = i.total
            records[_domain]['quota_count'] = i.quota_count

        # Get num of existing aliases and mailing lists.
        for (_sql_table, k) in [('alias', 'num_existing_aliases'),
                                ('maillists', 'num_existing_maillists')]:
            qr = conn.select(_sql_table,
                             vars=sql_vars,
                             what='domain, COUNT(address) AS total',
                             where='domain IN $domains',
                             group='domain',
                             limit=settings.PAGE_SIZE_LIMIT)

            for i in qr:
                _domain = str(i.domain).lower()
                records[_domain][k] = i.total

        # Sort domains by domain name
        _domains = list(records.keys())
        _domains.sort()
        _profiles = [records[k] for k in _domains]

        return True, _profiles
    except Exception as e:
        return False, repr(e)


def assign_given_mailbox_quota(domain,
                               quota,
                               domain_profile=None,
                               conn=None,
                               reset_user_quota=False,
                               user=None):
    """Check whether there's enough spare quota for creating new mail user.

    domain -- an existing domain name
    quota -- request new mailbox quota
    domain_profile -- existing domain profile (a dict)
    conn -- existing SQL connection cursor
    reset_user_quota -- Reset user quota. if it's trying to reset user quota,
                        we should add old user quota before calculating a new one
    """
    try:
        quota = abs(int(quota))
    except:
        # Wait for setting to per-domain default user quota.
        quota = -1

    if not conn:
        _wrap = SQLWrap()
        conn = _wrap.conn

    # Get domain profile first.
    if not domain_profile:
        qr = simple_profile(conn=conn, domain=domain)
        if qr[0]:
            domain_profile = qr[1]
        else:
            return qr

    # Get domain settings
    _ps = domain_profile.get('settings', '')
    ds = sqlutils.account_settings_string_to_dict(_ps)

    default_user_quota = ds.get('default_user_quota', 0)
    max_user_quota = ds.get('max_user_quota', 0)

    # Set to per-domain default user quota if quota is invalid
    if quota < 0:
        quota = default_user_quota

    # Re-calculate mail quota if this domain has limited max quota.
    domain_quota = domain_profile.get('maxquota', 0)
    if domain_quota > 0:
        # Get used quota.
        allocated_quota = get_allocated_domain_quota(domains=[domain], conn=conn)
        spare_quota = domain_profile.maxquota - allocated_quota

        # Add old quota before calculating new quota
        if reset_user_quota and user:
            try:
                qr = conn.select('mailbox',
                                 vars={'user': user},
                                 what='quota',
                                 where='username=$user',
                                 limit=1)
                if qr:
                    old_quota = int(qr[0].quota)
                    spare_quota = spare_quota + old_quota
            except Exception as e:
                return False, repr(e)

        if spare_quota > 0:
            if spare_quota < quota:
                quota = spare_quota
        else:
            # No enough quota.
            return False, 'EXCEEDED_DOMAIN_QUOTA_SIZE'

        if quota == 0:
            if default_user_quota:
                quota = default_user_quota
            elif max_user_quota:
                quota = max_user_quota
            else:
                quota = spare_quota

    if max_user_quota > 0:
        if quota > max_user_quota:
            quota = max_user_quota

    return True, quota


def assign_given_domain_quota(domain,
                              quota,
                              domain_profile=None,
                              conn=None):
    """Check whether specified domain quota is allowed to use.

    domain -- an existing domain name
    quota -- new domain quota (in MB)
    domain_profile -- existing domain profile (a dict)
    conn -- existing SQL connection cursor
    """
    try:
        quota = abs(int(quota))
    except:
        return False, 'INVALID_QUOTA_SIZE'

    admin = session.get('username')
    if session.get("is_global_admin"):
        return True, quota
    elif session.get('create_new_domains'):
        if not conn:
            _wrap = SQLWrap()
            conn = _wrap.conn

        # Get max domain quota from per-admin settings
        limits = sql_lib_admin.get_per_admin_domain_creation_limits(admin=admin, conn=conn)
        num_max_quota = limits['num_max_quota']
        allocated_quota = limits['num_allocated_quota']
        if num_max_quota > 0:
            # Get quota of current domain
            if not domain_profile:
                qr = simple_profile(domain=domain, conn=conn, columns=['maxquota'])
                if qr[0]:
                    domain_profile = qr[1]
                else:
                    return qr

            current_quota = int(domain_profile.maxquota)
            spare_quota = num_max_quota - (allocated_quota - current_quota)

            if spare_quota >= 0:
                if quota == 0:
                    quota = spare_quota
                elif quota >= spare_quota:
                    quota = spare_quota
            else:
                # don't change
                quota = current_quota

        return True, quota
    else:
        return False, 'PERMISSION_DENIED'


def get_domain_admin_addresses(domain, conn=None):
    """List email addresses of all domain admins (exclude global admins).

    >>> get_domain_admin_addresses(domain='abc.com')
    (True, ['user1@<domain>.com', 'user2@<domain>.com', ...])

    >>> get_domain_admin_addresses(domain='xyz.com')
    (False, '<reason>')
    """
    all_admins = set()
    sql_vars = {'domain': domain}
    try:
        if not conn:
            _wrap = SQLWrap()
            conn = _wrap.conn

        qr = conn.select('domain_admins',
                         vars=sql_vars,
                         what='username',
                         where='domain=$domain')

        for i in qr:
            all_admins.add(str(i.username).lower())

        return True, list(all_admins)
    except Exception as e:
        return False, repr(e)


def assign_admins_to_domain(domain, admins, conn=None):
    """Assign list of NEW admins to specified mail domain.

    It doesn't remove existing admins."""
    if not iredutils.is_domain(domain):
        return False, 'INVALID_DOMAIN_NAME'

    if not isinstance(admins, (list, tuple, set)):
        return False, 'NO_ADMINS'
    else:
        admins = [str(i).lower() for i in admins if iredutils.is_email(i)]
        if not admins:
            return False, 'NO_ADMINS'

    if not conn:
        _wrap = SQLWrap()
        conn = _wrap.conn

    for adm in admins:
        try:
            conn.insert('domain_admins',
                        domain=domain,
                        username=adm)
        except Exception as e:
            if e.__class__.__name__ == 'IntegrityError':
                pass
            else:
                return False, repr(e)

    return True,


def remove_default_maillists_in_domain_setting(domain, maillists, conn=None):
    """Remove given mailing list from domain.settings: default_groups."""
    domain = str(domain).lower()
    if not iredutils.is_domain(domain):
        return True,

    maillists = [str(i).lower() for i in maillists if iredutils.is_email(i)]
    if not maillists:
        return True,

    if not conn:
        _wrap = SQLWrap()
        conn = _wrap.conn

    # Get domain profile.
    qr = simple_profile(conn=conn,
                        domain=domain,
                        columns=['settings'])

    if qr[0]:
        domain_profile = qr[1]
        domain_settings = sqlutils.account_settings_string_to_dict(domain_profile['settings'])
    elif qr[1] == 'INVALID_DOMAIN_NAME':
        # No such domain, return earlier
        return True,
    else:
        return qr

    default_groups = domain_settings.get('default_groups', [])

    new_default_groups = [str(v).lower()
                          for v in default_groups
                          if v not in maillists]

    if default_groups != new_default_groups:
        if new_default_groups:
            domain_settings['default_groups'] = new_default_groups
        else:
            if 'default_groups' in domain_settings:
                domain_settings.pop('default_groups')

        new_domain_settings = sqlutils.account_settings_dict_to_string(domain_settings)

        try:
            conn.update('domain',
                        vars={'domain': domain},
                        settings=new_domain_settings,
                        modified=iredutils.get_gmttime(),
                        where='domain=$domain')
        except Exception as e:
            return False, repr(e)

    return True,


def update_ownership_verified_domain(primary_domain, alias_domain=None, conn=None):
    if not conn:
        _wrap = SQLWrap()
        conn = _wrap.conn

    is_alias_domain = False
    if primary_domain and alias_domain:
        is_alias_domain = True

    try:
        sql_vars = {
            'primary_domain': primary_domain,
            'alias_domain': alias_domain,
        }

        if is_alias_domain:
            conn.update('alias_domain',
                        vars=sql_vars,
                        active=1,
                        where='alias_domain=$alias_domain AND target_domain=$primary_domain AND active=0')
        else:
            conn.update('domain',
                        vars=sql_vars,
                        active=1,
                        where='domain=$primary_domain AND active=0')

        return True,
    except Exception as e:
        return False, repr(e)


def enable_domain_without_ownership_verification(domains, conn=None):
    domains = list({str(d).lower() for d in domains if iredutils.is_domain(d)})
    if not domains:
        return True,

    if not conn:
        _wrap = SQLWrap()
        conn = _wrap.conn

    _alias_domains = []

    # Query all matched alias domains
    try:
        qr = conn.select('alias_domain',
                         vars={'domains': domains},
                         what='alias_domain',
                         where='alias_domain IN $domains')
        for i in qr:
            _alias_domains += [str(i.alias_domain).lower()]

        _primary_domains = [d for d in domains if d not in _alias_domains]
    except Exception as e:
        return False, repr(e)

    for d in _primary_domains:
        # Enable domain directly
        try:
            conn.update('domain',
                        vars={'domain': d},
                        where="domain=$domain",
                        active=1)
            # Mark domains as verified
            msg = 'passed by global admin: %s' % session.get('username')
            qr = domain_ownership.mark_ownership_as_verified(domain=d, message=msg)
            if not qr[0]:
                return qr
        except Exception as e:
            return False, repr(e)

    for d in _alias_domains:
        try:
            conn.update('alias_domain',
                        vars={'domain': d},
                        where="alias_domain=$domain",
                        active=1)

            # Mark domains as verified
            msg = 'passed by global admin: %s' % session.get('username')
            qr = domain_ownership.mark_ownership_as_verified(domain=d, message=msg)
            if not qr[0]:
                return qr
        except Exception as e:
            return False, repr(e)

    return True,


@decorators.require_domain_access
def api_update_profile(domain, form, conn=None):
    """Update domain profile.

    :param domain: domain name.
    :param form: dict of web form.
    :param conn: sql connection cursor.

    Form parameters:

    `name`: the short company/orgnization name
    `accountStatus`: enable or disable domain. possible value is: active, disabled.
    `quota`: Per-domain mailbox quota
    `transport`: Per-domain transport

    `language`: default preferred language for new user.
                e.g. en_US for English, de_DE for Deutsch.

    `minPasswordLength`: Minimal password length
    `maxPasswordLength`: Maximum password length

    `defaultQuota`: default mailbox quota for new user.
    `maxUserQuota`: Max mailbox quota of a single mail user

    `numberOfUsers`: Max number of mail user accounts
    `numberOfAliases`: Max number of mail alias accounts

    `senderBcc`: set bcc address for outgoing emails
    `recipientBcc`: set bcc address for incoming emails

    `catchall`: set per-domain catch-all account.
                catchall account is a list of email addresses which will
                receive emails sent to non-existing address under same
                domain

    `outboundRelay`: relay outgoing emails to specified host

    `addService`: enable new services. Multiple services must be separated by comma.
    `removeService`: disable existing services. Multiple services must be separated by comma.
    `services`: reset all services. If empty, all existing services will be removed.

    `disableDomainProfile`: disable given domain profiles. Normal admin
                            cannot view and update disabled profiles in
                            domain profile page.
    `enableDomainProfile`: enable given domain profiles. Normal admin
                           can view and update disabled profiles in
                           domain profile page.
    `disableUserProfile`: disable given user profiles. Normal admin
                          cannot view and update disabled profiles in
                          user profile page.
    `enableUserProfile`: enable given domain profiles. Normal admin
                         can view and update disabled profiles in
                         user profile page.
    `disableUserPreference`: disable given user preferences in
                             self-service page. Normal mail user cannot
                             view and update disabled preferences.
    `enableUserPreference`: disable given user preferences in
                             self-service page. Normal mail user can
                             view and update disabled preferences.
    `aliasDomains`: remove all existing alias domains and add given
                    domains as alias domains. Multiple domains must be
                    separated by comma.
    `addAliasDomain`: add new alias domains. Multiple domains must be
                      separated by comma.
    `removeAliasDomain`: remove existing alias domains. Multiple
                         domains must be separated by comma.
    """
    domain = str(domain).lower()

    if not conn:
        _wrap = SQLWrap()
        conn = _wrap.conn

    params = {}

    # Name
    kv = form_utils.get_form_dict(form=form,
                                  input_name='name',
                                  key_name='description')
    params.update(kv)

    # Account status
    kv = form_utils.get_form_dict(form=form,
                                  input_name='accountStatus',
                                  key_name='active')
    params.update(kv)

    # Transport
    kv = form_utils.get_form_dict(form=form,
                                  input_name='transport',
                                  to_string=True)
    params.update(kv)

    # Backup MX (Require IP address or hostname of primary MX)
    if 'is_backupmx' in form:
        if form.get('is_backupmx') == 'yes':
            params.update({'backupmx': 1})

            v = form_utils.get_single_value(form,
                                            input_name='primarymx',
                                            to_string=True)

            if v:
                params.update({'transport': 'relay:%s' % v})
            else:
                params.update({'transport': 'relay:%s' % domain})
        else:
            params['backupmx'] = 0

            if 'transport' not in params:
                params.update({'transport': settings.default_mta_transport})

    db_settings = iredutils.get_settings_from_db()

    #
    # Domain settings stored in column `settings`
    #
    if {'language', 'defaultQuota', 'maxUserQuota',
            'minPasswordLength', 'maxPasswordLength',
            'disableDomainProfile', 'enableDomainProfile',
            'disableUserProfile', 'enableUserProfile',
            'disableUserPreference', 'enableUserPreference',
            'services', 'addService', 'removeService'} & set(form):
        # Get current account settings in dict
        qr = sql_lib_general.get_domain_settings(domain=domain, conn=conn)
        if qr[0]:
            _as = qr[1]
        else:
            return qr

        # Update settings
        kv = form_utils.get_form_dict(form=form,
                                      input_name='language',
                                      key_name='default_language',
                                      to_string=True)
        _as.update(kv)

        kv = form_utils.get_form_dict(form=form,
                                      input_name='minPasswordLength',
                                      key_name='min_passwd_length',
                                      is_integer=True)
        if not session.get('is_global_admin'):
            if kv:
                if kv['minPasswordLength'] < db_settings['min_passwd_length']:
                    kv['minPasswordLength'] = db_settings['min_passwd_length']

        _as.update(kv)

        kv = form_utils.get_form_dict(form=form,
                                      input_name='maxPasswordLength',
                                      key_name='max_passwd_length',
                                      is_integer=True)
        if not session.get('is_global_admin'):
            if kv:
                if kv['maxPasswordLength'] > db_settings['max_passwd_length'] or \
                   kv['maxPasswordLength'] <= db_settings['min_passwd_length']:
                    kv['maxPasswordLength'] = db_settings['max_passwd_length']

        _as.update(kv)

        kv = form_utils.get_form_dict(form=form,
                                      input_name='defaultQuota',
                                      key_name='default_user_quota',
                                      is_integer=True)
        _as.update(kv)

        kv = form_utils.get_form_dict(form=form,
                                      input_name='maxUserQuota',
                                      key_name='max_user_quota',
                                      is_integer=True)
        _as.update(kv)

        if session.get('is_global_admin'):
            # Enable/disabled mail services
            if 'addService' in form or 'removeService' in form:
                enabled_services = _as.get('enabled_services', [])
                new_enabled_services = set()

                if 'addService' in form:
                    kv = form_utils.get_form_dict(form=form, input_name='addService')

                    # Convert comma-separated services to list.
                    if kv:
                        _srvs = [str(srv).strip().lower()
                                 for srv in kv['addService'].split(',') if srv]
                        new_enabled_services.update(_srvs)

                if 'removeService' in form:
                    kv = form_utils.get_form_dict(form=form, input_name='removeService')

                    # Convert comma-separated services to list.
                    if kv:
                        _srvs = [str(srv).strip().lower()
                                 for srv in kv['removeService'].split(',') if srv]
                        new_enabled_services -= set(_srvs)

                if set(enabled_services) == new_enabled_services:
                    return True,
                else:
                    _as['enabled_services'] = list(new_enabled_services)

            if 'services' in form:
                _services = list({str(i).lower() for i in form.get('services', '').split(',') if i})

                if _services:
                    _as['enabled_services'] = _services
                else:
                    _as['enabled_services'] = []

            #
            # Enable/disabled domain profiles
            #
            _disabled = [('disableDomainProfile', 'disabled_domain_profiles'),
                         ('disableUserProfile', 'disabled_user_profiles'),
                         ('disableUserPreference', 'disabled_user_preferences')]
            _enabled = [('enableDomainProfile', 'disabled_domain_profiles'),
                        ('enableUserProfile', 'disabled_user_profiles'),
                        ('enableUserPreference', 'disabled_user_preferences')]

            for (_form_input_name, _key) in _disabled:
                # Disabled profiles
                if _form_input_name in form:
                    _values = set(_as.get(_key, []))

                    _v = form_utils.get_multi_values_from_api(form=form,
                                                              input_name=_form_input_name,
                                                              to_string=True,
                                                              to_lowercase=True)
                    _values.update(_v)
                    _as[_key] = _values

            for (_form_input_name, _key) in _enabled:
                # Enabled profiles
                if _form_input_name in form:
                    _values = set(_as.get(_key, []))

                    _v = form_utils.get_multi_values_from_api(form=form,
                                                              input_name=_form_input_name,
                                                              to_string=True,
                                                              to_lowercase=True)

                    for i in _v:
                        _values.discard(i)

                    _as[_key] = _values

        _as = sqlutils.account_settings_dict_to_string(_as)
        params['settings'] = _as

    if session.get('is_global_admin'):
        # Quota
        kv = form_utils.get_form_dict(form=form,
                                      input_name='quota',
                                      key_name='maxquota',
                                      is_integer=True)
        params.update(kv)

        # Number of users
        kv = form_utils.get_form_dict(form=form,
                                      input_name='numberOfUsers',
                                      key_name='mailboxes',
                                      is_integer=True)
        params.update(kv)

        # Number of aliases
        kv = form_utils.get_form_dict(form=form,
                                      input_name='numberOfAliases',
                                      key_name='aliases',
                                      is_integer=True)
        params.update(kv)

    #
    # Sender/Recipient bcc
    #
    sbcc = None
    rbcc = None
    if 'senderBcc' in form:
        sbcc = form_utils.get_single_value(form=form,
                                           input_name='senderBcc',
                                           is_email=True,
                                           to_lowercase=True)

    if 'recipientBcc':
        rbcc = form_utils.get_single_value(form=form,
                                           input_name='recipientBcc',
                                           is_email=True,
                                           to_lowercase=True)

    # Catch-all
    _c = form_utils.get_single_value(form=form,
                                     input_name='catchall',
                                     to_lowercase=True)
    _addresses = _c.strip(' ').split(',')
    qr = __update_catchall(domain=domain,
                           catchall=_addresses,
                           conn=conn)
    if not qr[0]:
        return qr

    # Outbound relay
    _relay = form_utils.get_single_value(form=form,
                                         input_name='outboundRelay',
                                         to_lowercase=True)
    qr = sql_lib_general.update_sender_relayhost(account=domain,
                                                 relayhost=_relay,
                                                 conn=conn)
    if not qr[0]:
        return qr

    #
    # Alias domains
    #
    if 'aliasDomains' in form:
        # Reset alias domains
        _alias_domains = form_utils.get_multi_values_from_api(form=form,
                                                              input_name='aliasDomains',
                                                              is_domain=True)
        _qr = __reset_alias_domains(domain=domain, alias_domains=_alias_domains, conn=conn)
        if not _qr[0]:
            return _qr
    else:
        _new_alias_domains = []
        _removed_alias_domains = []

        if 'addAliasDomain' in form:
            _new_alias_domains = form_utils.get_multi_values_from_api(form=form,
                                                                      input_name='addAliasDomain',
                                                                      is_domain=True)

        if 'removeAliasDomain' in form:
            _removed_alias_domains = form_utils.get_multi_values_from_api(form=form,
                                                                          input_name='removeAliasDomain',
                                                                          is_domain=True)

        _qr = __update_alias_domains(domain=domain,
                                     new_alias_domains=_new_alias_domains,
                                     removed_alias_domains=_removed_alias_domains,
                                     conn=conn)
        if not _qr[0]:
            return _qr

    if not (params or sbcc or rbcc):
        return True,

    try:
        sql_vars = {'domain': domain}

        if params:
            params['modified'] = iredutils.get_gmttime()
            conn.update('domain',
                        vars=sql_vars,
                        where='domain=$domain',
                        **params)

            msg = 'Update domain profile ({}): {}'.format(domain, ', '.join(list(params.keys())))
            log_activity(msg=msg,
                         admin=session.get('username'),
                         domain=domain,
                         event='update')

        if sbcc:
            qr = __update_sender_bcc(domain=domain,
                                     bcc_address=sbcc,
                                     conn=conn)

            if qr[0]:
                log_activity(msg='Update domain profile (%s): sender bcc' % domain,
                             admin=session.get('username'),
                             domain=domain,
                             event='update')
            else:
                return qr

        if rbcc:
            qr = __update_recipient_bcc(domain=domain,
                                        bcc_address=rbcc,
                                        conn=conn)

            if qr[0]:
                log_activity(msg='Update domain profile (%s): recipient bcc' % domain,
                             admin=session.get('username'),
                             domain=domain,
                             event='update')
            else:
                return qr

        return True,
    except Exception as e:
        return False, e


@decorators.require_domain_access
def api_update_domain_admins(domain, form, conn=None):
    """Update domain admins.

    @addAdmin - Add new domain admin. Multiple admins must be separated by comma.
    @removeAdmin - Remove existing domain admin. Multiple admins must be separated by comma.
    @removeAllAdmins - Remove all existing domain admins.

    Notes:
        - global admin can promote standalone admins to be a domain admin (or delete).
        - normal domain admin can promote mail user to be a domain admin (or delete).
    """
    domain = str(domain).lower()

    if not conn:
        _wrap = SQLWrap()
        conn = _wrap.conn

    if 'removeAllAdmins' in form:
        try:
            if session.get('is_global_admin'):
                # Remove all directly
                conn.delete('domain_admins',
                            vars={'domain': domain},
                            where='domain=$domain')
                return True,
            else:
                # Remove admins under control.
                managed_domains = []
                _qr = sql_lib_admin.get_managed_domains(conn=conn,
                                                        admin=session.get('username'),
                                                        domain_name_only=True,
                                                        listed_only=True)
                if _qr[0]:
                    managed_domains = _qr[1]

                # Get all current domain admins
                all_existing_admins = []
                _qr = get_domain_admin_addresses(domain=domain, conn=conn)
                if _qr[0]:
                    all_existing_admins = _qr[1]

                # Remove admins under control
                removed_admins = [v for v in all_existing_admins
                                  if v.split('@', 1)[-1] in managed_domains]

                conn.delete('domain_admins',
                            vars={'domain': domain, 'admins': removed_admins},
                            where='domain=$domain AND username IN $admins')

                for adm in removed_admins:
                    sql_lib_admin.revoke_admin_privilege_if_no_managed_domains(admin=adm, conn=conn)

                log_activity(msg='Remove all domain (%s) admins' % domain,
                             admin=session.get('username'),
                             domain=domain,
                             event='update')
        except Exception as e:
            return False, repr(e)

    else:
        if not ('addAdmin' in form or 'removeAdmin' in form):
            return True,

        # Get all standalone admins if API requestor is a global admin.
        existing_standalone_admins = []

        # Get all managed domains if API requestor is not a global admin.
        managed_domains = []

        if session.get('is_global_admin'):
            try:
                qr = conn.select('admin', what='username')
                for i in qr:
                    existing_standalone_admins.append(str(i.username).lower())
            except Exception as e:
                return False, repr(e)
        else:
            # Get managed domains
            qr = sql_lib_admin.get_managed_domains(conn=conn,
                                                   admin=session.get('username'),
                                                   domain_name_only=True,
                                                   listed_only=True)
            if qr[0]:
                managed_domains = qr[1]

        # Get new separated admins
        new_standalone_admins = []

        # Get new admins which are mail user accounts
        new_user_admins = []

        if 'addAdmin' in form:
            kv = form_utils.get_form_dict(form=form, input_name='addAdmin')

            # Convert comma-separated values to list.
            if kv:
                _vs = [str(v).strip().lower()
                       for v in kv['addAdmin'].split(',')
                       if iredutils.is_email(v)]

                new_admins = [str(v).lower().strip()
                              for v in _vs if iredutils.is_email(v)]

                if new_admins:
                    sql_vars = {
                        'domain': domain,
                        'new_admins': new_admins,
                    }

                    if session.get('is_global_admin'):
                        new_standalone_admins = [v for v in new_admins if v in existing_standalone_admins]

                        qr = conn.select('mailbox',
                                         vars=sql_vars,
                                         what='username,isadmin',
                                         where='username IN $new_admins')
                    else:
                        qr = conn.select('mailbox',
                                         vars={'managed_domains': managed_domains, 'new_admins': new_admins},
                                         what='username,isadmin',
                                         where='domain IN $managed_domains AND username IN $new_admins')

                    for r in qr:
                        _user = str(r.username).lower()
                        new_user_admins.append(_user)

                        if r.isadmin != 1:
                            conn.update('mailbox',
                                        vars={'user': _user},
                                        isadmin=1,
                                        where='username=$user')

                    _all_new_admins = new_standalone_admins + new_user_admins
                    for _admin in _all_new_admins:
                        try:
                            conn.insert('domain_admins',
                                        username=_admin,
                                        domain=domain,
                                        active=1)
                        except Exception as e:
                            if e.__class__.__name__ == 'IntegrityError':
                                pass
                            else:
                                return False, repr(e)

                    if _all_new_admins:
                        msg = 'Add new domain ({}) admins: {}'.format(domain, ', '.join(_all_new_admins))
                        log_activity(msg=msg,
                                     admin=session.get('username'),
                                     domain=domain,
                                     event='update')

        if 'removeAdmin' in form:
            kv = form_utils.get_form_dict(form=form, input_name='removeAdmin')

            # Convert comma-separated services to list.
            if kv:
                _vs = [str(v).strip().lower()
                       for v in kv['removeAdmin'].split(',')
                       if iredutils.is_email(v)]

                removed_admins = [str(v).lower().strip()
                                  for v in _vs
                                  if iredutils.is_email(v)]

                if removed_admins:
                    if session.get('is_global_admin'):
                        # Remove from `vmail.domain_admins` directly.
                        try:
                            conn.delete('domain_admins',
                                        vars={'domain': domain, 'admins': removed_admins},
                                        where='domain=$domain AND username IN $admins')

                            msg = 'Remove domain ({}) admins: {}'.format(domain, ', '.join(removed_admins))
                            log_activity(msg=msg,
                                         admin=session.get('username'),
                                         domain=domain,
                                         event='update')
                        except Exception as e:
                            return False, repr(e)
                    else:
                        # Check whether admins exist
                        try:
                            qr = conn.select('mailbox',
                                             vars={'managed_domains': managed_domains,
                                                   'removed_admins': removed_admins},
                                             what='username',
                                             where='domain IN $managed_domains AND username IN $removed_admins')

                            removed_existing_admins = []
                            for i in qr:
                                _user = str(i.username).lower()
                                removed_existing_admins.append(_user)

                            if removed_existing_admins:
                                conn.delete('domain_admins',
                                            vars={'domain': domain,
                                                  'admins': removed_existing_admins},
                                            where='domain=$domain AND username IN $admins')

                                msg = 'Remove domain ({}) admins: {}'.format(domain, ', '.join(removed_existing_admins))
                                log_activity(msg=msg,
                                             admin=session.get('username'),
                                             domain=domain,
                                             event='update')
                        except Exception as e:
                            return False, repr(e)

                    for adm in removed_admins:
                        sql_lib_admin.revoke_admin_privilege_if_no_managed_domains(admin=adm, conn=conn)

    return True,


def get_first_char_of_all_domains(conn=None):
    """Get first character of all domains."""
    if not conn:
        _wrap = SQLWrap()
        conn = _wrap.conn

    admin = session.get('username')
    chars = []
    try:
        if sql_lib_general.is_global_admin(admin=admin, conn=conn):
            qr = conn.select('domain',
                             what='SUBSTRING(domain FROM 1 FOR 1) AS first_char',
                             group='first_char')
        else:
            qr = conn.query("""SELECT SUBSTRING(domain.domain FROM 1 FOR 1) AS first_char
                                 FROM domain
                            LEFT JOIN domain_admins ON (domain.domain=domain_admins.domain)
                                WHERE domain_admins.username=$admin
                             GROUP BY first_char""",
                            vars={'admin': admin})

        if qr:
            chars = [i.first_char.upper() for i in qr]
            chars.sort()

        return True, chars
    except Exception as e:
        logger.error(e)
        return False, repr(e)
