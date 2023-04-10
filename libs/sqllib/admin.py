# Author: Zhang Huangbin <zhb@iredmail.org>

import web
import settings
from libs import iredutils, iredpwd, form_utils
from libs.logger import log_traceback, log_activity
from libs.sqllib import SQLWrap, auth, sqlutils
from libs.sqllib import general as sql_lib_general

session = web.config.get('_session', {})


def is_admin_exists(conn, admin):
    # Return True if account is invalid or exist.
    admin = str(admin).lower()
    if not iredutils.is_email(admin):
        return True

    try:
        qr = conn.select(
            'admin',
            vars={'username': admin},
            what='username',
            where='username=$username',
            limit=1,
        )

        if qr:
            # Exists.
            return True

        return False
    except:
        # Return True as exist to not allow to create new domain/account.
        return True


def num_admins(conn):
    # Count separated admin accounts
    num = 0
    qr = conn.select('admin', what='COUNT(username) AS total')
    if qr:
        num = qr[0].total or 0

    return num


def num_user_admins(conn):
    # Count number of users which are marked as admins
    num = 0
    qr = conn.select(
        'mailbox',
        what='COUNT(username) AS total',
        where='isadmin=1 OR isglobaladmin=1',
    )
    if qr:
        num = qr[0].total or 0

    return num


def get_all_admins(columns=None, email_only=False, conn=None):
    """List all admins. Return (True, [records])."""
    sql_what = '*'
    if columns:
        sql_what = ','.join(columns)

    records = []
    try:
        if not conn:
            _wrap = SQLWrap()
            conn = _wrap.conn

        # standalone admin accounts
        qr = conn.select('admin',
                         what=sql_what,
                         order='username')

        for i in qr:
            records += [i]

        # mail users with admin privileges
        qr = conn.select('mailbox',
                         what=sql_what,
                         where='isadmin=1 OR isglobaladmin=1',
                         order='username')

        for i in qr:
            records += [i]

        if email_only:
            _emails = []

            for rcd in records:
                _mail = str(rcd.username).lower()
                if _mail not in _emails:
                    _emails += [_mail]

            _emails.sort()

            return True, _emails

        return True, records
    except Exception as e:
        log_traceback()
        return False, repr(e)


def get_paged_admins(conn, cur_page=1):
    # Get current page.
    cur_page = int(cur_page)

    sql_limit = ''
    if cur_page > 0:
        sql_limit = 'LIMIT %d OFFSET %d' % (
            settings.PAGE_SIZE_LIMIT,
            (cur_page - 1) * settings.PAGE_SIZE_LIMIT,
        )

    try:
        # Get number of total accounts
        total = num_admins(conn) + num_user_admins(conn)

        # Get records
        # Separate admins
        qr_admins = conn.query(
            """
            SELECT name, username, language, active
              FROM admin
          ORDER BY username ASC
            %s
            """ % sql_limit
        )

        qr_user_admins = conn.query(
            """
            SELECT name, username, language, active, isadmin, isglobaladmin
              FROM mailbox
             WHERE (isadmin=1 OR isglobaladmin=1)
          ORDER BY username ASC
            %s
            """ % sql_limit
        )
        return True, {'total': total, 'records': list(qr_admins) + list(qr_user_admins)}
    except Exception as e:
        log_traceback()
        return False, repr(e)


def get_paged_domain_admins(conn,
                            domain,
                            include_global_admins=False,
                            columns=None,
                            current_page=1,
                            first_char=None):
    """Get all admins who have privilege to manage specified domain."""
    if columns:
        sql_what = ','.join(columns)
    else:
        sql_what = '*'

    if include_global_admins:
        sql_where = """username IN (
                       SELECT username FROM domain_admins
                       WHERE domain IN ('%s', 'ALL'))""" % domain
    else:
        sql_where = """username IN (
                       SELECT username FROM domain_admins
                       WHERE domain='%s')""" % domain

    if first_char:
        sql_where += ' AND username LIKE %s' % web.sqlquote(first_char.lower() + '%')

    total = 0
    all_admins = []
    try:
        qr_total = conn.select('mailbox',
                               what='COUNT(username) AS total',
                               where=sql_where)

        if qr_total:
            total = qr_total[0].total or 0
            qr = conn.select('mailbox',
                             what=sql_what,
                             where=sql_where,
                             limit=settings.PAGE_SIZE_LIMIT,
                             offset=(current_page - 1) * settings.PAGE_SIZE_LIMIT)

            for i in qr:
                all_admins += [i]

        return True, {'total': total, 'records': all_admins}
    except Exception as e:
        log_traceback()
        return False, repr(e)


def get_all_global_admins(conn=None):
    admins = []

    try:
        if not conn:
            _wrap = SQLWrap()
            conn = _wrap.conn

        qr = conn.select('domain_admins',
                         what='username',
                         where="domain='ALL'")

        for r in qr:
            admins += [str(r.username).lower()]

        admins.sort()
        return True, admins
    except Exception as e:
        log_traceback()
        return False, repr(e)


# Get domains under control.
def get_managed_domains(admin,
                        domain_name_only=False,
                        listed_only=False,
                        conn=None):
    admin = str(admin).lower()

    if not iredutils.is_email(admin):
        return False, 'INCORRECT_USERNAME'

    if not conn:
        _wrap = SQLWrap()
        conn = _wrap.conn

    try:
        if sql_lib_general.is_global_admin(admin=admin, conn=conn):
            if listed_only:
                result = conn.query(
                    """
                    SELECT domain.domain
                      FROM domain
                 LEFT JOIN domain_admins ON (domain.domain=domain_admins.domain)
                     WHERE domain_admins.username=$admin
                     ORDER BY domain_admins.domain
                    """,
                    vars={'admin': admin})
            else:
                result = conn.select('domain',
                                     what='domain',
                                     order='domain')
        else:
            sql_left_join = ''
            if not listed_only:
                sql_left_join = """OR domain_admins.domain='ALL'"""

            result = conn.query(
                """
                SELECT domain.domain
                  FROM domain
             LEFT JOIN domain_admins ON (domain.domain=domain_admins.domain %s)
                 WHERE domain_admins.username=$admin
              ORDER BY domain_admins.domain
                """ % sql_left_join,
                vars={'admin': admin})

        if domain_name_only:
            domains = []
            for i in result:
                _domain = str(i['domain']).lower()
                if iredutils.is_domain(_domain):
                    domains.append(_domain)

            return True, domains
        else:
            return True, list(result)
    except Exception as e:
        log_traceback()
        return False, repr(e)


def num_managed_domains(admin=None,
                        disabled_only=False,
                        first_char=None,
                        conn=None):
    num = 0

    if not admin:
        admin = session.get('username')

    if not conn:
        _wrap = SQLWrap()
        conn = _wrap.conn

    sql_where = ''
    if disabled_only:
        sql_where += 'domain.active=0'

    if first_char:
        first_char = first_char[0].lower()

        if sql_where:
            sql_where += ' AND domain.domain LIKE %s' % web.sqlquote(first_char + '%')
        else:
            sql_where += 'domain.domain LIKE %s' % web.sqlquote(first_char + '%')

    try:
        if sql_lib_general.is_global_admin(admin=admin, conn=conn):
            qr = conn.select('domain', what='COUNT(domain) AS total', where=sql_where or None)
        else:
            if sql_where:
                sql_where = 'AND ' + sql_where

            qr = conn.query(
                """
                SELECT COUNT(domain.domain) AS total
                FROM domain
                LEFT JOIN domain_admins ON (domain.domain=domain_admins.domain)
                WHERE domain_admins.username=$admin %s
                """ % sql_where,
                vars={'admin': admin})

        num = qr[0].total or 0
    except:
        log_traceback()

    return num


def num_managed_users(admin=None, domains=None, conn=None, listed_only=False):
    """Count users of all managed domains."""
    num = 0

    if not admin:
        admin = session.get('username')

    if not conn:
        _wrap = SQLWrap()
        conn = _wrap.conn

    if domains:
        domains = [str(d).lower() for d in domains if iredutils.is_domain(d)]
    else:
        qr = get_managed_domains(conn=conn,
                                 admin=admin,
                                 domain_name_only=True,
                                 listed_only=listed_only)
        if qr[0]:
            domains = qr[1]

    if not domains:
        return num

    sql_vars = {'admin': admin, 'domains': domains}

    try:
        if sql_lib_general.is_global_admin(admin=admin, conn=conn):
            if domains:
                qr = conn.select('mailbox',
                                 vars=sql_vars,
                                 what='COUNT(username) AS total',
                                 where='domain IN $domains')
            else:
                qr = conn.select('mailbox', what='COUNT(username) AS total')
        else:
            sql_append_where = ''
            if domains:
                sql_append_where = 'AND mailbox.domain IN %s' % web.sqlquote(domains)

            qr = conn.query(
                """
                SELECT COUNT(mailbox.username) AS total
                FROM mailbox
                LEFT JOIN domain_admins ON (mailbox.domain = domain_admins.domain)
                WHERE domain_admins.username=$admin %s
                """ % sql_append_where,
                vars=sql_vars,
            )

        num = qr[0].total or 0
    except:
        log_traceback()

    return num


def __num_allocated_accounts(admin=None,
                             domains=None,
                             conn=None,
                             listed_only=False):
    """Count allocated users/aliases/lists of all managed domains."""
    num = {'users': 0, 'aliases': 0, 'lists': 0}

    if not admin:
        admin = session.get('username')

    if not conn:
        _wrap = SQLWrap()
        conn = _wrap.conn

    if domains:
        domains = [str(d).lower() for d in domains if iredutils.is_domain(d)]
    else:
        qr = get_managed_domains(conn=conn,
                                 admin=admin,
                                 domain_name_only=True,
                                 listed_only=listed_only)
        if qr[0]:
            domains = qr[1]

    if not domains:
        return num

    sql_vars = {'admin': admin, 'domains': domains}

    try:
        if sql_lib_general.is_global_admin(admin=admin, conn=conn):
            sql_what = 'SUM(mailboxes) AS mailboxes, SUM(aliases) AS aliases, SUM(maillists) AS maillists'

            if domains:
                qr = conn.select('domain',
                                 vars=sql_vars,
                                 what=sql_what,
                                 where='domain IN $domains')
            else:
                qr = conn.select('domain', what=sql_what)
        else:
            sql_what = 'SUM(domain.mailboxes) AS mailboxes, SUM(domain.aliases) AS aliases, SUM(domain.maillists) as maillists'

            sql_append_where = ''
            if domains:
                sql_append_where = 'AND domain.domain IN %s' % web.sqlquote(domains)

            qr = conn.query("""
                            SELECT %s
                            FROM domain
                            LEFT JOIN domain_admins ON (domain.domain = domain_admins.domain)
                            WHERE domain_admins.username=$admin %s
                            """ % (sql_what, sql_append_where),
                            vars=sql_vars)

        if qr:
            _qr = list(qr)[0]
            num['users'] = int(_qr.mailboxes) or 0
            num['aliases'] = int(_qr.aliases) or 0
            num['lists'] = int(_qr.maillists) or 0
    except:
        log_traceback()

    return num


def num_managed_aliases(admin=None, domains=None, listed_only=False, conn=None):
    """Count aliases of all managed domains."""
    num = 0

    if not admin:
        admin = session.get('username')

    if not conn:
        _wrap = SQLWrap()
        conn = _wrap.conn

    if domains:
        domains = [str(d).lower() for d in domains if iredutils.is_domain(d)]
    else:
        qr = get_managed_domains(admin=admin,
                                 domain_name_only=True,
                                 listed_only=listed_only,
                                 conn=conn)
        if qr[0]:
            domains = qr[1]

    if not domains:
        return num

    sql_vars = {'admin': admin, 'domains': domains}

    try:
        if sql_lib_general.is_global_admin(admin=admin, conn=conn):
            if domains:
                qr = conn.select('alias', what='COUNT(address) AS total')
            else:
                qr = conn.select('alias',
                                 vars=sql_vars,
                                 what='COUNT(address) AS total',
                                 where='domain IN $domains')
        else:
            qr = conn.select('alias',
                             vars=sql_vars,
                             what='COUNT(address) AS total',
                             where='domain IN $domains')

        num = qr[0].total or 0
    except:
        log_traceback()

    return num


def num_managed_lists(admin=None, domains=None, listed_only=False, conn=None):
    """Count mailing lists under all managed domains."""
    num = 0

    if not admin:
        admin = session.get('username')

    if not conn:
        _wrap = SQLWrap()
        conn = _wrap.conn

    if domains:
        domains = [str(d).lower() for d in domains if iredutils.is_domain(d)]
    else:
        qr = get_managed_domains(admin=admin,
                                 domain_name_only=True,
                                 listed_only=listed_only,
                                 conn=conn)
        if qr[0]:
            domains = qr[1]

    if not domains:
        return num

    sql_vars = {'admin': admin, 'domains': domains}

    try:
        if sql_lib_general.is_global_admin(admin=admin, conn=conn):
            if domains:
                qr = conn.select('maillists', what='COUNT(address) AS total')
            else:
                qr = conn.select('maillists',
                                 vars=sql_vars,
                                 what='COUNT(address) AS total',
                                 where='domain IN $domains')
        else:
            qr = conn.select('maillists',
                             vars=sql_vars,
                             what='COUNT(address) AS total',
                             where='domain IN $domains')

        num = qr[0].total or 0
    except:
        log_traceback()

    return num


def sum_all_allocated_domain_quota(admin=None,
                                   domains=None,
                                   listed_only=True,
                                   conn=None):
    """Sum all allocated quota of managed domains.

    :returns (True, <int>) if success.
    :returns (False, <error_reason>) if failed to sum.
    """
    num = 0

    if not admin:
        admin = session.get('username')

    if not conn:
        _wrap = SQLWrap()
        conn = _wrap.conn

    if not domains:
        qr = get_managed_domains(conn=conn,
                                 admin=admin,
                                 domain_name_only=True,
                                 listed_only=listed_only)
        if qr[0]:
            domains = qr[1]

    if not domains:
        return True, num

    # Get allocated quota
    try:
        qr = conn.select('domain',
                         vars={'domains': domains},
                         what='maxquota',
                         where='domain IN $domains')

        for i in qr:
            if i.maxquota:
                num += i.maxquota

        return True, int(num)
    except Exception as e:
        log_traceback()
        return False, repr(e)


def sum_all_used_quota(conn):
    """Sum all used quota. Return a dict: {'messages': x, 'bytes': x}."""
    d = {'messages': 0, 'bytes': 0}

    admin = session.get('username')
    if sql_lib_general.is_global_admin(admin=admin, conn=conn):
        qr = conn.query("""SELECT SUM(messages) AS messages,
                                  SUM(bytes) AS bytes
                             FROM %s""" % settings.SQL_TBL_USED_QUOTA)
        row = qr[0]
        d['messages'] = row.messages
        d['bytes'] = row.bytes

    return d


def add_admin_from_form(form, conn=None):
    mail = web.safestr(form.get('mail')).strip().lower()

    if not iredutils.is_email(mail):
        return False, 'INVALID_MAIL'

    # Get new password.
    newpw = web.safestr(form.get('newpw'))
    confirmpw = web.safestr(form.get('confirmpw'))

    qr = iredpwd.verify_new_password(newpw=newpw, confirmpw=confirmpw)
    if qr[0]:
        passwd = qr[1]
    else:
        return qr

    if not conn:
        _wrap = SQLWrap()
        conn = _wrap.conn

    # Check local domain
    domain = mail.split('@', 1)[-1]
    if not iredutils.is_domain(domain):
        return False, 'INVALID_DOMAIN'

    if sql_lib_general.is_domain_exists(domain=domain, conn=conn):
        return False, 'CAN_NOT_BE_LOCAL_DOMAIN'

    # Check admin exist.
    if is_admin_exists(conn=conn, admin=mail):
        return False, 'ALREADY_EXISTS'

    is_global_admin = False
    _is_global_admin = form_utils.get_single_value(form=form, input_name='domainGlobalAdmin', default_value='no')
    if _is_global_admin == 'yes':
        is_global_admin = True

    # Name, language
    cn = form.get('cn', '')
    lang = form_utils.get_language(form)
    _status = form_utils.get_single_value(form=form, input_name='accountStatus', default_value='active')
    if _status == 'active':
        _status = 1
    else:
        _status = 0

    # Account settings.
    _as = {}

    # Domain creation settings
    _cs = form_utils.get_domain_creation_settings(form=form)
    _as.update(_cs)

    if 'disable_viewing_mail_log' in form:
        _as['disable_viewing_mail_log'] = 'yes'

    if 'disable_managing_quarantined_mails' in form:
        _as['disable_managing_quarantined_mails'] = 'yes'

    try:
        conn.insert('admin',
                    username=mail,
                    name=cn,
                    password=iredpwd.generate_password_hash(passwd),
                    language=lang,
                    created=iredutils.get_gmttime(),
                    settings=sqlutils.account_settings_dict_to_string(_as),
                    active=_status)

        if is_global_admin:
            conn.insert('domain_admins',
                        username=mail,
                        domain='ALL',
                        created=iredutils.get_gmttime(),
                        active='1')

        log_activity(msg="Create admin: %s." % mail, event='create')
        return True,
    except Exception as e:
        log_traceback()
        return False, repr(e)


def get_profile(mail, columns=None, conn=None):
    if not iredutils.is_email(mail):
        return False, 'INVALID_MAIL'

    if isinstance(columns, (list, tuple, set)):
        columns = ','.join(columns)
    else:
        columns = '*'

    if not conn:
        _wrap = SQLWrap()
        conn = _wrap.conn

    try:
        qr = conn.select('admin',
                         vars={'username': mail},
                         what=columns,
                         where='username=$username',
                         limit=1)

        if qr:
            return True, list(qr)[0]
        else:
            return False, 'NO_SUCH_ACCOUNT'
    except Exception as e:
        log_traceback()
        return False, repr(e)


def delete_admins(mails, revoke_admin_privilege_from_user=True, conn=None):
    mails = [str(v) for v in mails if iredutils.is_email(v)]

    if not mails:
        return True,

    sql_vars = {'mails': mails}

    try:
        if not conn:
            _wrap = SQLWrap()
            conn = _wrap.conn

        # Standalone mail admins
        conn.delete('admin',
                    vars=sql_vars,
                    where='username IN $mails')

        conn.delete('domain_admins',
                    vars=sql_vars,
                    where='username IN $mails')

        # Unmark global/domain admin which is mail user
        if revoke_admin_privilege_from_user:
            conn.update('mailbox',
                        vars=sql_vars,
                        where='username IN $mails AND (isadmin=1 OR isglobaladmin=1)',
                        isadmin=0,
                        isglobaladmin=0)

        log_activity(event='delete', msg="Delete admin(s): %s." % ', '.join(mails))

        return True,
    except Exception as e:
        log_traceback()
        return False, repr(e)


# Domain administration relationship (stored in sql table `domain_admins`)
# Normal domain admin will have records for each managed domain, global admin
# has only one record:
#
#   - normal admin: "username=<mail> AND domain='<domain>'"
#   - global admin: "username=<mail> AND domain='ALL'"
# NOTE: word 'ALL' is in upper cases.
def update(mail, profile_type, form, conn=None):
    mail = str(mail).lower()

    # Don't allow to view/update other admins' profile.
    if mail != session.get('username') and not session.get('is_global_admin'):
        return False, 'PERMISSION_DENIED'

    sql_vars = {'username': mail}

    if not conn:
        _wrap = SQLWrap()
        conn = _wrap.conn

    params = {}
    if profile_type == 'general':
        # Name, preferred language
        params['name'] = form.get('cn', '')
        params['language'] = form_utils.get_language(form)

        # Update language immediately.
        if session.get('username') == mail and session.get('lang') != params['language']:
            session['lang'] = params['language']

        tz_name = form_utils.get_timezone(form)
        qr = sql_lib_general.update_admin_settings(
            conn=conn,
            mail=mail,
            new_settings={"timezone": tz_name},
        )
        if not qr[0]:
            return qr

        if session.get('is_global_admin'):
            # Update account status
            params['active'] = 0
            if 'accountStatus' in form:
                params['active'] = 1

            # Check and set global admin type.
            mark_as_global_admin = False
            if 'domainGlobalAdmin' in form:
                mark_as_global_admin = True

            # Update managed domains.
            # Get domains from web form.
            try:
                # Delete existing admin privileges
                conn.delete('domain_admins',
                            vars=sql_vars,
                            where='username=$username')
            except Exception as e:
                log_traceback()
                return False, repr(e)

            if mark_as_global_admin:
                # Insert new record to become a global admin
                try:
                    conn.insert('domain_admins',
                                username=mail,
                                created=iredutils.get_gmttime(),
                                domain='ALL',
                                active=params['active'])

                    # Update domain admin type in session immediately.
                    if session.get('username') == mail and (not mark_as_global_admin):
                        session['is_global_admin'] = False
                except Exception as e:
                    log_traceback()
                    return False, repr(e)

            else:
                newmds = form_utils.get_domain_names(form)
                if newmds:
                    # Insert new managed domains.
                    sql_inserts = []

                    for d in newmds:
                        sql_inserts += [{'username': mail,
                                         'domain': d,
                                         'created': iredutils.get_gmttime(),
                                         'active': 1}]

                    conn.multiple_insert('domain_admins', values=sql_inserts)

            #
            # If marked as normal domain admin, allow to create new domains
            #
            _new_settings = {}
            _removed_settings = []

            if mark_as_global_admin:
                _removed_settings = ['create_new_domains', 'create_max_domains',
                                     'create_max_users', 'create_max_aliases',
                                     'create_max_lists',
                                     'create_max_quota', 'create_quota_unit',
                                     'disable_domain_ownership_verification',
                                     'disable_viewing_mail_log',
                                     'disable_managing_quarantined_mails']
            else:
                for i in ['create_max_domains', 'create_max_quota',
                          'create_max_users', 'create_max_aliases',
                          'create_max_lists']:
                    if i in form:
                        try:
                            v = int(form.get(i, '0'))
                        except:
                            v = 0

                        if v > 0:
                            _new_settings[i] = v
                        else:
                            _removed_settings.append(i)

                for i in ['disable_domain_ownership_verification',
                          'disable_viewing_mail_log',
                          'disable_managing_quarantined_mails']:
                    if i in form:
                        _new_settings[i] = 'yes'
                    else:
                        _removed_settings.append(i)

                if _new_settings:
                    _new_settings['create_new_domains'] = 'yes'
                else:
                    _removed_settings += ['create_new_domains']

                if 'create_max_quota' in _new_settings:
                    if 'create_quota_unit' in form:
                        v = form.get('create_quota_unit', 'TB')
                        if v in ['TB', 'GB']:
                            _new_settings['create_quota_unit'] = v
                        else:
                            _removed_settings += ['create_quota_unit']

                if _new_settings:
                    qr = sql_lib_general.update_admin_settings(conn=conn,
                                                               mail=mail,
                                                               new_settings=_new_settings)
                    if not qr[0]:
                        return qr

                if _removed_settings:
                    qr = sql_lib_general.update_admin_settings(conn=conn,
                                                               mail=mail,
                                                               removed_settings=_removed_settings)
                    if not qr[0]:
                        return qr
    elif profile_type == 'password':
        cur_passwd = web.safestr(form.get('oldpw', ''))
        newpw = web.safestr(form.get('newpw', ''))
        confirmpw = web.safestr(form.get('confirmpw', ''))

        # Verify new passwords.
        qr = iredpwd.verify_new_password(newpw=newpw, confirmpw=confirmpw)
        if qr[0]:
            passwd = iredpwd.generate_password_hash(qr[1])

            params['password'] = passwd
            params['passwordlastchange'] = iredutils.get_gmttime()
        else:
            return qr

        if not session.get('is_global_admin'):
            # Verify old password.
            qr = auth.auth(conn=conn,
                           username=mail,
                           password=cur_passwd,
                           account_type='admin',
                           verify_password=True)

            if not qr[0]:
                return qr

    if params:
        try:
            conn.update('admin',
                        vars=sql_vars,
                        where='username=$username',
                        **params)
        except Exception as e:
            log_traceback()
            if 'password' in params:
                raise web.seeother('/profile/admin/password/{}?msg={}'.format(mail, web.urlquote(e)))
            else:
                raise web.seeother('/profile/admin/general/{}?msg={}'.format(mail, web.urlquote(e)))

    return True,


def revoke_admin_privilege_if_no_managed_domains(admin=None, conn=None):
    """If given admin doesn't manage any domain, revoke the admin privilege.

    @admin -- email address of domain admin
    @conn -- sql connection cursor
    """
    if not admin:
        return True,

    if not conn:
        _wrap = SQLWrap()
        conn = _wrap.conn

    # Return immediately if it's a global admin
    if sql_lib_general.is_global_admin(admin=admin, conn=conn):
        return True,

    if not num_managed_domains(admin=admin, conn=conn):
        try:
            conn.update('mailbox',
                        vars={'admin': admin},
                        isadmin=0,
                        where='username=$admin')
        except Exception as e:
            log_traceback()
            return False, repr(e)

    return True,


def get_per_admin_domain_creation_limits(admin=None, conn=None):
    """Get per-admin domain creation limits for normal domain admin.

    Return a dict of all limits."""
    # `-1` means no limit.
    data = {
        # Whether current admin is allowed to create new mail domain
        'create_new_domain': True,

        # Short error message used to identify why current admin is not
        # allowed to create new domain
        'error_code': [],

        # number of currently managed and allowed max domains
        'num_managed_domains': 0,
        'num_max_domains': 0,
        'num_spare_domains': -1,

        # number of currently allocated and allowed max quota, in MB
        'num_allocated_quota': 0,
        'num_max_quota': 0,
        'num_spare_quota': -1,

        # number of allocated and allowed max users
        'num_max_users': 0,
        'num_allocated_users': 0,
        'num_spare_users': -1,

        # number of allocated and allowed max aliases
        'num_max_aliases': 0,
        'num_allocated_aliases': 0,
        'num_spare_aliases': -1,

        # number of allocated and allowed max mailing lists
        'num_max_lists': 0,
        'num_allocated_lists': 0,
        'num_spare_lists': -1,
    }

    if not admin:
        admin = session.get('username')

    # Return immediately if no need to check such limits
    if admin == session.get('username'):
        if session.get('is_global_admin'):
            return data

    if not conn:
        _wrap = SQLWrap()
        conn = _wrap.conn

    #
    # check max domains, max quota
    #
    # Get per-account settings first
    qr = sql_lib_general.get_admin_settings(admin=admin, conn=conn)
    if qr[0]:
        _as = qr[1]
    else:
        raise web.seeother('/domains?msg=%s' % web.urlquote(qr[1]))

    # List of managed domain names
    managed_domains = []

    if ('create_max_domains' in _as) or \
       ('create_max_users' in _as) or \
       ('create_max_aliases' in _as) or \
       ('create_max_quota' in _as and 'create_quota_unit' in _as):
        # Get managed domains
        qr = get_managed_domains(admin=admin,
                                 domain_name_only=True,
                                 listed_only=True,
                                 conn=conn)
        if qr[0]:
            data['managed_domains'] = qr[1]
            data['num_managed_domains'] = len(data['managed_domains'])
        else:
            raise web.seeother('/domains?msg=%s' % web.urlquote(qr[1]))

        if 'create_max_domains' in _as:
            data['num_max_domains'] = _as['create_max_domains']

            if data['num_max_domains'] > 0:
                if data['num_max_domains'] <= data['num_managed_domains']:
                    data['create_new_domain'] = False
                    data['error_code'] += ['EXCEED_LIMIT_DOMAIN']
                else:
                    data['num_spare_domains'] = data['num_max_domains'] - data['num_managed_domains']

        # Get allocated quota
        if 'create_max_quota' in _as:
            data['num_max_quota'] = _as['create_max_quota']
            _max_quota_unit = _as.get('create_quota_unit', 'MB')

            if _max_quota_unit == 'TB':
                data['num_max_quota'] = data['num_max_quota'] * 1024 * 1024
            else:
                # GB
                data['num_max_quota'] = data['num_max_quota'] * 1024

            qr = sum_all_allocated_domain_quota(admin=admin,
                                                domains=managed_domains,
                                                conn=conn)

            if qr[0]:
                data['num_allocated_quota'] = qr[1]
            else:
                raise web.seeother('/domains?msg=%s' % web.urlquote(qr[1]))

            if data['num_max_quota'] > 0:
                if data['num_max_quota'] <= data['num_allocated_quota']:
                    data['create_new_domain'] = False
                    data['error_code'] += ['EXCEED_LIMIT_QUOTA']
                    data['num_spare_quota'] = 0
                else:
                    data['num_spare_quota'] = data['num_max_quota'] - data['num_allocated_quota']

        # check existing users
        if 'create_max_users' in _as or \
           'create_max_aliases' in _as or \
           'create_max_lists' in _as:
            data['num_max_users'] = _as.get('create_max_users', -1)
            data['num_max_aliases'] = _as.get('create_max_aliases', -1)
            data['num_max_lists'] = _as.get('create_max_lists', -1)

            qr = __num_allocated_accounts(admin=admin,
                                          listed_only=True,
                                          conn=conn)
            data['num_allocated_users'] = qr['users']
            data['num_allocated_aliases'] = qr['aliases']
            data['num_allocated_lists'] = qr['lists']

            if data['num_max_users'] > 0:
                if data['num_max_users'] <= data['num_allocated_users']:
                    data['create_new_domain'] = False
                    data['error_code'] += ['EXCEED_LIMIT_USERS']
                    data['num_spare_users'] = 0
                else:
                    data['num_spare_users'] = data['num_max_users'] - data['num_allocated_users']

            if data['num_max_aliases'] > 0:
                if data['num_max_aliases'] <= data['num_allocated_aliases']:
                    data['create_new_domain'] = False
                    data['error_code'] += ['EXCEED_LIMIT_ALIASES']
                    data['num_spare_aliases'] = 0
                else:
                    data['num_spare_aliases'] = data['num_max_aliases'] - data['num_allocated_aliases']

            if data['num_max_lists'] > 0:
                if data['num_max_lists'] <= data['num_allocated_lists']:
                    data['create_new_domain'] = False
                    data['error_code'] += ['EXCEED_LIMIT_LISTS']
                    data['num_spare_lists'] = 0
                else:
                    data['num_spare_lists'] = data['num_max_lists'] - data['num_allocated_lists']
    else:
        if admin == session.get('username'):
            session['create_new_domains'] = False

    return data


def api_update_profile(form, mail, conn=None):
    """Update profile of existing standalone domain admin.

    @param form: dict of the web form.
    @param mail: admin email address.
    @param conn: sql connection cursor.

    Form parameters:

    `name`: the display name of this admin
    `password`: admin password
    `accountStatus`: account status (active, disabled)
    `isGlobalAdmin`: Mark this admin as global admin (yes, no).
    `language`: default preferred language for new user.

    Form parameters listed below are used by normal domain admin. With
    `isGlobalAdmin=yes`, they will be removed.

    `maxDomains`: how many mail domains this admin can create.
    `maxQuota`: how much mailbox quota this admin can create.
                Quota is shared by all domains created/managed by this
                admin. Sample: 10TB, 20GB, 100MB.
    `maxUsers`: number of mail users this admin can create.
                It's shared by all domains created/managed by this admin.
    `maxAliases`: number of mail aliases this admin can create.
                  It's shared by all domains created/managed by this admin.
    `maxLists`: how many mailing lists this admin can create.
                It's shared by all domains created/managed by this admin.
    `disableViewingMailLog`: Disallow this admin to view log of
                             inbound/outbound mails. (yes, no)
    `disableManagingQuarantinedMails`: Disallow this admin to manage
                                       quarantined mails. (yes, no)
    """
    mail = str(mail).lower()

    params = {}

    # Get password
    if 'password' in form:
        qr = form_utils.get_password(form=form,
                                     input_name='password',
                                     confirm_pw_input_name='password',
                                     min_passwd_length=settings.min_passwd_length,
                                     max_passwd_length=settings.max_passwd_length)
        if qr[0]:
            pw_hash = qr[1]['pw_hash']
            params.update({'password': pw_hash})
        else:
            return qr

    # Name
    kv = form_utils.get_form_dict(form=form, input_name='name')
    params.update(kv)

    # Account status
    kv = form_utils.get_form_dict(form=form,
                                  input_name='accountStatus',
                                  key_name='active')
    params.update(kv)

    # Language
    kv = form_utils.get_form_dict(form=form,
                                  input_name='language')
    params.update(kv)

    if not conn:
        _wrap = SQLWrap()
        conn = _wrap.conn

    # Get account settings first.
    qr = sql_lib_general.get_admin_settings(admin=mail, conn=conn)
    if qr[0]:
        _as = qr[1]
        _as_orig = _as.copy()
    else:
        return qr

    # [(api_form_name, web_form_name), ...]
    for (k_api, k_web) in [('disableViewingMailLog', 'disable_viewing_mail_log'),
                           ('disableManagingQuarantinedMails', 'disable_managing_quarantined_mails')]:
        kv = form_utils.get_form_dict(form=form,
                                      input_name=k_api,
                                      key_name=k_web)
        if kv:
            (k, v) = list(kv.items())[0]
            if v == 'yes':
                _as[k] = 'yes'
            elif v == 'no':
                if k in _as:
                    _as.pop(k)

    # global admin
    if 'isGlobalAdmin' in form:
        _is_global_admin = form_utils.get_single_value(form=form,
                                                       input_name='isGlobalAdmin',
                                                       default_value='no')
        if _is_global_admin == 'yes':
            try:
                conn.delete('domain_admins',
                            vars={'admin': mail},
                            where="""username=$admin AND domain='ALL'""")

                conn.insert('domain_admins',
                            username=mail,
                            domain='ALL',
                            created=iredutils.get_gmttime(),
                            active=1)
            except Exception as e:
                log_traceback()
                return False, repr(e)
        else:
            conn.delete('domain_admins',
                        vars={'admin': mail},
                        where="""username=$admin AND domain='ALL'""")

            _d = form_utils.get_domain_creation_settings(form=form)
            _as.update(_d)

    if _as != _as_orig:
        _as = sqlutils.account_settings_dict_to_string(_as)
        params.update({'settings': _as})

    if params:
        try:
            conn.update('admin',
                        vars={'mail': mail},
                        where='username=$mail',
                        **params)
        except Exception as e:
            log_traceback()
            return False, repr(e)

    return True,
