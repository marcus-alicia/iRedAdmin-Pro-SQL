# Author: Zhang Huangbin <zhb@iredmail.org>

import time
import web

import settings

from libs import iredutils
from libs.logger import logger


if settings.backend == 'ldap':
    from libs.ldaplib.admin import get_managed_domains
else:
    from libs.sqllib.admin import get_managed_domains

session = web.config.get('_session')


def __get_managed_domains():
    domains = []

    kw = {'admin': session.get('username'),
          'domain_name_only': True,
          'conn': None}

    if settings.backend != 'ldap':
        kw['listed_only'] = True

    qr = get_managed_domains(**kw)

    if qr[0]:
        domains = qr[1]

    return domains


def get_num_rejected(hours=None):
    """Return amount of rejected mails in last given `hours`."""
    num = 0

    if not hours:
        hours = 24

    sql_vars = {
        "action": "REJECT",
        "time_num": (int(time.time()) - (hours * 3600)),
    }

    sql_wheres = ["action = $action AND time_num >= $time_num"]

    if not session.get('is_global_admin'):
        domains = __get_managed_domains()

        if domains:
            sql_vars['domains'] = domains
            sql_wheres += ['(sender_domain IN $domains OR sasl_username IN $domains OR recipient_domain IN $domains)']
        else:
            return num

    sql_where = ' AND '.join(sql_wheres)

    try:
        qr = web.conn_iredapd.select(
            'smtp_sessions',
            vars=sql_vars,
            what="COUNT(id) AS total",
            where=sql_where,
        )
        if qr:
            num = qr[0]['total']
    except Exception as e:
        logger.error(e)

    return num


def get_num_smtp_outbound_sessions(hours=None):
    """Return amount of smtp authentications in last given `hours`."""
    num = 0

    if not hours:
        hours = 24

    sql_vars = {
        "time_num": (int(time.time()) - (hours * 3600)),
    }

    sql_wheres = ["sasl_username <> '' AND time_num >= $time_num"]

    if not session.get('is_global_admin'):
        domains = __get_managed_domains()

        if domains:
            sql_vars['domains'] = domains
            sql_wheres += ['sasl_domain IN $domains']
        else:
            return num

    sql_where = ' AND '.join(sql_wheres)

    try:
        qr = web.conn_iredapd.select(
            'smtp_sessions',
            vars=sql_vars,
            what="COUNT(id) AS total",
            where=sql_where,
        )

        if qr:
            num = qr[0]['total']
    except Exception as e:
        logger.error(e)

    return num


def get_log_smtp_sessions(domains=None,
                          sasl_usernames=None,
                          senders=None,
                          recipients=None,
                          client_addresses=None,
                          encryption_protocols=None,
                          outbound_only=False,
                          rejected_only=False,
                          offset=None,
                          limit=None):
    """Return a dict with amount of smtp rejections and list of (SQL) rows."""
    result = {'total': 0, 'rows': []}

    if not offset or not isinstance(offset, int):
        offset = 0

    if not limit or not isinstance(limit, int):
        limit = settings.PAGE_SIZE_LIMIT

    query_domains = []
    sql_vars = {}
    sql_wheres = []
    sql_where = None

    if domains:
        query_domains = [str(i).lower() for i in domains if iredutils.is_domain(i)]

    if session.get('is_global_admin'):
        if query_domains:
            sql_vars['domains'] = query_domains

            if outbound_only:
                sql_wheres += ['sasl_domain IN $domains']
            else:
                sql_wheres += ['(sender_domain IN $domains OR sasl_domain IN $domains OR recipient_domain IN $domains)']
        else:
            if outbound_only:
                sql_wheres += ["sasl_username <> ''"]
    else:
        managed_domains = __get_managed_domains()
        if not managed_domains:
            return result

        if domains:
            query_domains = [str(i).lower() for i in domains if i in managed_domains]

            if not query_domains:
                return result
        else:
            query_domains = managed_domains

        sql_vars['domains'] = query_domains
        if outbound_only:
            sql_wheres += ['sasl_domain in $domains']
        else:
            sql_wheres += ['(sender_domain IN $domains OR sasl_domain IN $domains OR recipient_domain IN $domains)']

    if sasl_usernames:
        sql_vars['sasl_usernames'] = [str(i).lower() for i in sasl_usernames if iredutils.is_email(i)]
        sql_wheres += ['sasl_username IN $sasl_usernames']

    if senders:
        sql_vars['senders'] = [str(i).lower() for i in senders if iredutils.is_email(i)]
        sql_wheres += ['sender IN $senders']

    if recipients:
        sql_vars['recipients'] = [str(i).lower() for i in recipients if iredutils.is_email(i)]
        sql_wheres += ['recipient IN $recipients']

    if client_addresses:
        sql_vars['client_addresses'] = [i for i in client_addresses if iredutils.is_strict_ip(i)]
        sql_wheres += ['client_address IN $client_addresses']

    if encryption_protocols:
        sql_vars['encryption_protocols'] = encryption_protocols
        sql_wheres += ['encryption_protocol IN $encryption_protocols']

    if rejected_only:
        sql_wheres += ["action='REJECT'"]

    if sql_wheres:
        sql_where = ' AND '.join(sql_wheres)

    try:
        qr = web.conn_iredapd.select(
            'smtp_sessions',
            vars=sql_vars,
            what='COUNT(id) AS total',
            where=sql_where,
        )
        if qr:
            result['total'] = qr[0].total
    except Exception as e:
        logger.error(e)

    columns = [
        'id', 'time', 'time_num',
        'action', 'reason', 'instance',
        'sasl_username', 'sender', 'recipient',
        'client_address', 'encryption_protocol',
    ]

    try:
        qr = web.conn_iredapd.select(
            'smtp_sessions',
            vars=sql_vars,
            what=','.join(columns),
            where=sql_where,
            order='time_num DESC',
            offset=offset,
            limit=limit,
        )

        if qr:
            result['rows'] = list(qr)
    except Exception as e:
        logger.error(e)

    return result


def get_smtp_insecure_outbound(hours=None):
    """
    Return info of insecure smtp outbound sessions in last given `hours`.

    (True, {'total': '<int>', 'usernames': [<mail>, <mail>, ...]})
    (False, '<error>')
    """
    result = {'total': 0, 'usernames': []}

    if not isinstance(hours, int):
        hours = 24

    sql_vars = {
        "time_num": (int(time.time()) - (hours * 3600)),
    }

    sql_wheres = ["sasl_username <> '' AND encryption_protocol = '' AND time_num >= $time_num"]

    if not session.get('is_global_admin'):
        domains = __get_managed_domains()

        if domains:
            sql_vars['domains'] = domains
            sql_wheres += ['sasl_domain IN $domains']
        else:
            return True, result

    sql_where = ' AND '.join(sql_wheres)

    try:
        qr = web.conn_iredapd.select(
            'smtp_sessions',
            vars=sql_vars,
            what='sasl_username',
            where=sql_where,
            group='sasl_username',
        )

        for row in qr:
            result['total'] += 1
            _email = str(row['sasl_username']).lower().strip()
            result['usernames'].append(_email)

        result['usernames'].sort()
        return True, result
    except Exception as e:
        logger.error(e)
        return False, repr(e)
