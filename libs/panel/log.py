# Author: Zhang Huangbin <zhb@iredmail.org>

import web

import settings
from libs import iredutils
from libs.panel import LOG_EVENTS

if settings.backend == 'ldap':
    from libs.ldaplib.general import is_domain_admin
    from libs.ldaplib.admin import get_managed_domains
else:
    from libs.sqllib.general import is_domain_admin
    from libs.sqllib.admin import get_managed_domains

session = web.config.get('_session')


def list_logs(event='all', domain='all', admin='all', cur_page=1):
    event = web.safestr(event)
    domain = web.safestr(domain)
    admin = web.safestr(admin)
    cur_page = int(cur_page)

    sql_vars = {}
    sql_wheres = []
    sql_where = ''

    if event not in LOG_EVENTS:
        event = "all"

    if event != 'all':
        sql_vars['event'] = event
        sql_wheres += ["event=$event"]

    if iredutils.is_domain(domain):
        if session.get('is_global_admin') or is_domain_admin(domain=domain, admin=session['username'], conn=None):
            sql_vars['domain'] = domain
            sql_wheres += ["domain=$domain"]
    else:
        # Get managed domains.
        if not session.get("is_global_admin"):
            if settings.backend == 'ldap':
                qr = get_managed_domains(admin=session["username"],
                                         attributes=None,
                                         domain_name_only=True,
                                         conn=None)

            else:
                qr = get_managed_domains(admin=session["username"],
                                         domain_name_only=True,
                                         listed_only=True,
                                         conn=None)
            if qr[0]:
                sql_vars["managed_domains"] = qr[1]
                sql_wheres += ["domain IN $managed_domains"]
            else:
                return qr

    if iredutils.is_email(admin):
        if session.get('is_global_admin'):
            sql_vars['admin'] = admin
            sql_wheres += ["admin=$admin"]
        else:
            sql_vars['admin'] = session.get('username')
            sql_wheres += ["admin=$admin"]
    else:
        if not session.get('is_global_admin'):
            sql_vars['admin'] = session.get('username')
            sql_wheres += ["admin=$admin"]

    # Get number of total records.
    if sql_wheres:
        sql_where = ' AND '.join(sql_wheres)

        qr = web.conn_iredadmin.select(
            'log',
            vars=sql_vars,
            what='COUNT(id) AS total',
            where=sql_where,
        )
    else:
        qr = web.conn_iredadmin.select('log', what='COUNT(id) AS total')

    total = qr[0].total or 0

    # Get records.
    if sql_wheres:
        qr = web.conn_iredadmin.select(
            'log',
            vars=sql_vars,
            where=sql_where,
            offset=(cur_page - 1) * settings.PAGE_SIZE_LIMIT,
            limit=settings.PAGE_SIZE_LIMIT,
            order='timestamp DESC',
        )
    else:
        # No addition filter.
        qr = web.conn_iredadmin.select(
            'log',
            offset=(cur_page - 1) * settings.PAGE_SIZE_LIMIT,
            limit=settings.PAGE_SIZE_LIMIT,
            order='timestamp DESC',
        )

    return total, list(qr)


def delete_logs(form, delete_all=False):
    if delete_all:
        try:
            web.conn_iredadmin.delete('log', where="1=1")
            return True,
        except Exception as e:
            return False, repr(e)
    else:
        ids = form.get('id', [])

        if ids:
            try:
                web.conn_iredadmin.delete('log', where="id IN %s" % web.db.sqlquote(ids))
                return True,
            except Exception as e:
                return False, repr(e)

    return True,
