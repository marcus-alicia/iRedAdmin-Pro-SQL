# Author: Zhang Huangbin <zhb@iredmail.org>

import web

from libs import iredutils
from libs.logger import log_activity
from libs.sqllib import SQLWrap
from libs.sqllib import domain as sql_lib_domain
from libs.sqllib import admin as sql_lib_admin
from libs.sqllib import user as sql_lib_user
from libs.sqllib import alias as sql_lib_alias
from libs.sqllib import ml as sql_lib_ml
from libs.sqllib import general as sql_lib_general

session = web.config.get('_session', {})


def set_account_status(conn,
                       accounts,
                       account_type,
                       enable_account=False):
    """Set account status.

    accounts -- an iterable object (list/tuple) filled with accounts.
    account_type -- possible value: domain, admin, user, alias, ml
    enable_account -- possible value: True, False
    """
    if account_type in ['admin', 'user', 'alias', 'maillist', 'ml']:
        # email
        accounts = [str(v).lower() for v in accounts if iredutils.is_email(v)]
    else:
        # domain name
        accounts = [str(v).lower() for v in accounts if iredutils.is_domain(v)]

    if not accounts:
        return True,

    # 0: disable, 1: enable
    account_status = 0
    action = 'disable'
    if enable_account:
        account_status = 1
        action = 'active'

    if account_type == 'domain':
        # handle with function which handles admin privilege
        qr = sql_lib_domain.enable_disable_domains(domains=accounts,
                                                   action=action)
        return qr
    elif account_type == 'admin':
        # [(<table>, <column-used-for-query>), ...]
        table_column_maps = [("admin", "username")]
    elif account_type == 'alias':
        table_column_maps = [
            ("alias", "address"),
            ("forwardings", "address"),
        ]
    elif account_type in ['maillist', 'ml']:
        table_column_maps = [("maillists", "address")]
    else:
        # account_type == 'user'
        table_column_maps = [
            ("mailbox", "username"),
            ("forwardings", "address"),
        ]

    for (_table, _column) in table_column_maps:
        sql_where = '{} IN {}'.format(_column, web.sqlquote(accounts))
        try:
            conn.update(_table,
                        where=sql_where,
                        active=account_status)

        except Exception as e:
            return False, repr(e)

    log_activity(event=action,
                 msg="{} {}: {}.".format(action.title(), account_type, ', '.join(accounts)))
    return True,


def delete_accounts(accounts,
                    account_type,
                    keep_mailbox_days=0,
                    conn=None):
    # accounts must be a list/tuple.
    # account_type in ['domain', 'user', 'admin', 'alias', 'ml']
    if not accounts:
        return True,

    if not conn:
        _wrap = SQLWrap()
        conn = _wrap.conn

    if account_type == 'domain':
        qr = sql_lib_domain.delete_domains(domains=accounts,
                                           keep_mailbox_days=keep_mailbox_days,
                                           conn=conn)
        return qr
    elif account_type == 'user':
        sql_lib_user.delete_users(accounts=accounts,
                                  keep_mailbox_days=keep_mailbox_days,
                                  conn=conn)
    elif account_type == 'admin':
        sql_lib_admin.delete_admins(mails=accounts, conn=conn)
    elif account_type == 'alias':
        sql_lib_alias.delete_aliases(conn=conn, accounts=accounts)
    elif account_type == 'ml':
        sql_lib_ml.delete_maillists(conn=conn, accounts=accounts)

    return True,


# Search accounts with display name, email.
def search(search_string,
           account_type=None,
           account_status=None,
           conn=None):
    """Return search result in dict.

    (True, {
            'domain': sql_query_result,
            'user': sql_query_result,
            ...
            }
    )
    """
    sql_vars = {
        'search_str': '%%' + search_string + '%%',
        'search_str_exclude_domain': '%%' + search_string + '%%@%%',
    }

    if not account_type:
        account_type = ['domain', 'user', 'alias', 'ml', 'admin']

    if not account_status:
        account_status = ['active', 'disabled']

    sql_where_domain_status = ''
    sql_where_admin_status = ''
    sql_where_user_status = ''
    sql_where_ml_status = ''
    sql_where_alias_status = ''
    sql_where_user_domain = ''
    sql_where_alias_domain = ''
    sql_where_ml_domain = ''

    if 'active' in account_status and 'disabled' in account_status:
        pass
    elif 'active' in account_status:
        sql_where_domain_status = ' AND domain.active=1'
        sql_where_admin_status = ' AND domain.active=1'
        sql_where_user_status = ' AND mailbox.active=1'
        sql_where_alias_status = ' AND alias.active=1'
        sql_where_ml_status = ' AND maillists.active=1'
    elif 'disabled' in account_status:
        sql_where_domain_status = ' AND domain.active=0'
        sql_where_admin_status = ' AND domain.active=0'
        sql_where_user_status = ' AND mailbox.active=0'
        sql_where_alias_status = ' AND alias.active=0'
        sql_where_ml_status = ' AND maillists.active=0'

    if not conn:
        _wrap = SQLWrap()
        conn = _wrap.conn

    # Get managed domains.
    if not session.get('is_global_admin'):
        qr = sql_lib_admin.get_managed_domains(admin=session.get('username'),
                                               domain_name_only=True,
                                               listed_only=True,
                                               conn=conn)

        if qr[0]:
            managed_domains = qr[1]
            sql_where_user_domain = ' AND mailbox.domain IN %s' % web.sqlquote(managed_domains)
            sql_where_alias_domain = ' AND alias.domain IN %s' % web.sqlquote(managed_domains)
            sql_where_ml_domain = ' AND maillists.domain IN %s' % web.sqlquote(managed_domains)
        else:
            raise web.seeother('/search?msg=%s' % web.urlquote(qr[1]))

    result = {
        'domain': [],
        'admin': [],
        'user': [],
        'ml': [],
        'last_logins': {},
        'user_alias_addresses': {},
        'user_forwarding_addresses': {},
        'user_assigned_groups': {},
        'alias': [],
        # List of email addresses of global admins.
        'allGlobalAdmins': [],
    }

    if session.get('is_global_admin'):
        if 'domain' in account_type:
            qr_domain = conn.select(
                'domain',
                vars=sql_vars,
                what='domain,description,aliases,mailboxes,maxquota,active',
                where='(domain LIKE $search_str OR description LIKE $search_str) %s' % sql_where_domain_status,
                order='domain',
            )

            if qr_domain:
                result['domain'] = iredutils.bytes2str(qr_domain)

        if 'admin' in account_type:
            qr_admin = conn.select(
                'admin',
                vars=sql_vars,
                what='username,name,active',
                where='(username LIKE $search_str OR name LIKE $search_str) %s' % sql_where_admin_status,
                order='username',
            )

            if qr_admin:
                result['admin'] = iredutils.bytes2str(qr_admin) or []

                # Get all global admin accounts.
                qr = sql_lib_admin.get_all_global_admins(conn=conn)
                if qr[0]:
                    result['allGlobalAdmins'] = qr[1]

    # Search user accounts.
    if 'user' in account_type:
        search_str_user = sql_vars['search_str_exclude_domain']
        if '@' in sql_vars['search_str']:
            search_str_user = sql_vars['search_str']
        sql_vars['search_str_user'] = search_str_user

        # Query users by email address or display name
        qr_user = conn.select(
            'mailbox',
            vars=sql_vars,
            what='username,name,quota,employeeid,active',
            where='(username LIKE $search_str_user OR name LIKE $search_str) {} {}'.format(sql_where_user_status, sql_where_user_domain),
            order='username')

        # Query users by per-user alias address
        qr_user_alias = conn.select(
            ['forwardings', 'mailbox'],
            vars=sql_vars,
            what='mailbox.username, mailbox.name, mailbox.quota, mailbox.employeeid, mailbox.active',
            where='(forwardings.address LIKE $search_str_user) AND forwardings.forwarding=mailbox.username AND forwardings.is_alias=1 {} {}'.format(sql_where_user_status, sql_where_user_domain),
            group='mailbox.username, mailbox.name, mailbox.quota, mailbox.employeeid, mailbox.active',
            order='mailbox.username')

        # Query users by mail forwarding address
        qr_user_forwarding = conn.select(
            ['forwardings', 'mailbox'],
            vars=sql_vars,
            what='mailbox.username, mailbox.name, mailbox.quota, mailbox.employeeid, mailbox.active',
            where='(forwardings.forwarding LIKE $search_str_user) AND forwardings.address=mailbox.username AND forwardings.is_forwarding=1 {} {}'.format(sql_where_user_status, sql_where_user_domain),
            group='mailbox.username, mailbox.name, mailbox.quota, mailbox.employeeid, mailbox.active',
            order='mailbox.username')

        if qr_user:
            result['user'] += iredutils.bytes2str(qr_user)

        if qr_user_alias:
            _records = iredutils.bytes2str(qr_user_alias)

            # Add new, remove duplicate records.
            for i in _records:
                if i not in result['user']:
                    result['user'] += [i]

        if qr_user_forwarding:
            _records = iredutils.bytes2str(qr_user_forwarding)

            # Add new, remove duplicate records.
            for i in _records:
                if i not in result['user']:
                    result['user'] += [i]

        # Get email addresses of returned user accounts
        _user_emails = []
        for i in result['user']:
            _user_emails.append(str(i['username']).lower())
        _user_emails.sort()

        # Get per-user alias and mail forwarding addresses
        if _user_emails:
            (_status, _result) = sql_lib_user.get_bulk_user_alias_addresses(mails=_user_emails, conn=conn)
            if _status:
                result['user_alias_addresses'] = _result

            (_status, _result) = sql_lib_user.get_bulk_user_forwardings(mails=_user_emails, conn=conn)
            if _status:
                result['user_forwarding_addresses'] = _result

            (_status, _result) = sql_lib_user.get_bulk_user_assigned_groups(mails=_user_emails, conn=conn)
            if _status:
                result['user_assigned_groups'] = _result

            # Get user last login
            result['last_logins'] = sql_lib_general.get_account_last_login(accounts=_user_emails, conn=conn)

    # Search alias accounts.
    if 'alias' in account_type:
        search_str_alias = sql_vars['search_str_exclude_domain']
        if '@' in sql_vars['search_str']:
            search_str_alias = sql_vars['search_str']
        sql_vars['search_str_alias'] = search_str_alias

        qr_alias = conn.select(
            'alias',
            vars=sql_vars,
            what='address,name,accesspolicy,domain,active',
            where='(address LIKE $search_str_alias OR name LIKE $search_str) {} {}'.format(
                sql_where_alias_status, sql_where_alias_domain,
            ),
            order='address',
        )

        if qr_alias:
            result['alias'] = iredutils.bytes2str(qr_alias) or []

    # Search mailing list accounts.
    if 'ml' in account_type:
        search_str_ml = sql_vars['search_str_exclude_domain']
        if '@' in sql_vars['search_str']:
            search_str_ml = sql_vars['search_str']
        sql_vars['search_str_ml'] = search_str_ml

        qr_ml = conn.select(
            'maillists',
            vars=sql_vars,
            what='address,name,accesspolicy,domain,active',
            where='(address LIKE $search_str_alias OR name LIKE $search_str) {} {}'.format(
                sql_where_ml_status, sql_where_ml_domain,
            ),
            order='address',
        )

        if qr_ml:
            result['ml'] = iredutils.bytes2str(qr_ml) or []

    if result:
        return True, result
    else:
        return False, []
