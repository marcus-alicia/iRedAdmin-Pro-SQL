# Author: Zhang Huangbin <zhb@iredmail.org>

import time
import web
import settings
from libs import iredutils
from libs.logger import logger, log_traceback
from libs.amavisd import MAIL_ID_CHARACTERS

session = web.config.get('_session')


# Import backend related modules.
if settings.backend == 'ldap':
    from libs.ldaplib import admin as ldap_lib_admin
elif settings.backend in ['mysql', 'pgsql']:
    from libs.sqllib import admin as sql_lib_admin


def delete_all_records(log_type=None, account=None):
    # Delete all records, or delete records older than one week.
    # :param log_type: sent, received
    # :param account: single email address, domain name, '@.'
    account_is_email = False
    account_is_domain = False
    maddr_ids = []
    managed_domains_reversed = []

    if account:
        if iredutils.is_email(account):
            account_is_email = True
        elif iredutils.is_domain(account):
            account_is_domain = True
        else:
            if account == '@.':
                pass
            else:
                return False, 'INVALID_ACCOUNT'

        # get `maddr.id` of this account
        if account_is_email:
            # user
            qr = web.conn_amavisd.select('maddr',
                                         vars={'account': account},
                                         what='id',
                                         where='email=$account',
                                         limit=1)
            if qr:
                maddr_ids.append(qr[0].id)
        elif account_is_domain:
            # domain
            reversed_domain = iredutils.reverse_amavisd_domain_names([account])[0]
            qr = web.conn_amavisd.select('maddr',
                                         vars={'account': reversed_domain},
                                         what='id',
                                         where='domain=$account')
            if qr:
                for r in qr:
                    maddr_ids.append(r.id)

        # no `maddr.id`, no mail log.
        if not maddr_ids:
            return True,
    else:
        if session.get('is_global_admin'):
            web.conn_amavisd.delete('msgs', where='1=1')
            web.conn_amavisd.delete('msgrcpt', where='1=1')
            return True,

        # Get all managed domains by normal admin.
        managed_domains = []
        if settings.backend == 'ldap':
            _qr = ldap_lib_admin.get_managed_domains(admin=session.get('username'))
            if _qr[0]:
                managed_domains = _qr[1]

        elif settings.backend in ['mysql', 'pgsql']:
            qr = sql_lib_admin.get_managed_domains(admin=session.get('username'),
                                                   domain_name_only=True)

            if qr[0]:
                managed_domains = qr[1]
        else:
            return False, 'UNKNOWN_BACKEND'

        managed_domains_reversed = iredutils.reverse_amavisd_domain_names(managed_domains)
        if not managed_domains_reversed:
            return True,

    try:
        # Delete records in tables: msgs, msgrcpt.
        if log_type == 'sent':
            if account:
                # Delete all records sent by single user
                web.conn_amavisd.delete('msgs',
                                        vars={'maddr_ids': maddr_ids},
                                        where='sid IN $maddr_ids')
            else:
                # Delete all records sent by domain users
                web.conn_amavisd.delete('msgs',
                                        vars={'managed_domains_reversed': managed_domains_reversed},
                                        where='sid IN (SELECT id FROM maddr WHERE domain IN $managed_domains_reversed)')

        elif log_type == 'received':
            if account:
                web.conn_amavisd.delete('msgs',
                                        vars={'maddr_ids': maddr_ids},
                                        where='mail_id IN (SELECT mail_id FROM msgrcpt WHERE rid IN $maddr_ids)')

                web.conn_amavisd.delete('msgrcpt',
                                        vars={'maddr_ids': maddr_ids},
                                        where='rid IN $maddr_ids')
            else:
                all_rcpt_ids = []   # maddr.id

                qr = web.conn_amavisd.select('maddr',
                                             vars={'domains': managed_domains_reversed},
                                             what='id',
                                             where='domain IN $domains')
                for i in qr:
                    all_rcpt_ids.append(i['id'])

                del qr

                web.conn_amavisd.delete('msgs',
                                        vars={'ids': all_rcpt_ids},
                                        where='mail_id IN (SELECT mail_id FROM msgrcpt WHERE rid IN $ids)')

                web.conn_amavisd.delete('msgrcpt',
                                        vars={'ids': all_rcpt_ids},
                                        where='rid IN $ids')

                del all_rcpt_ids

        return True,
    except Exception as e:
        return False, repr(e)


def delete_records_by_mail_id(log_type='sent', mail_ids=None):
    # log_type -- received, sent, quarantined, quarantine
    if not isinstance(mail_ids, list):
        return False, 'INCORRECT_MAILID'

    # Filter unexpected mail_id strings.
    mail_ids = [v for v in mail_ids if len(set(v) - set(MAIL_ID_CHARACTERS)) == 0]

    if not mail_ids:
        return True,

    # Converted into SQL style list.
    mail_ids = web.sqlquote(mail_ids)

    if log_type in ['received', 'sent', 'quarantined', 'quarantine']:
        try:
            # Delete records in tables: msgs, msgrcpt.
            web.conn_amavisd.delete('msgs', where='mail_id IN %s' % mail_ids)
            web.conn_amavisd.delete('msgrcpt', where='mail_id IN %s' % mail_ids)
        except Exception as e:
            return False, repr(e)

    if log_type in ['quarantined', 'quarantine']:
        try:
            web.conn_amavisd.delete('quarantine', where="mail_id IN %s" % mail_ids)
        except Exception as e:
            return False, repr(e)

    return True,


def count_incoming_mails(reversedDomainNames=None,
                         timeLength=None,
                         sqlAppendWhere=None):
    # timeLength is seconds.
    total = 0

    if not reversedDomainNames:
        if not session.get('account_is_mail_user'):
            return total

    if sqlAppendWhere:
        sql_append_where = sqlAppendWhere
    else:
        sql_append_where = ' AND recip.domain IN %s' % web.sqlquote(reversedDomainNames)

    if isinstance(timeLength, int):
        _now = int(time.time())
        _length_seconds = _now - timeLength
        sql_append_where += ' AND msgs.time_num > %d' % _length_seconds

    try:
        qr = web.conn_amavisd.query('''
                        -- Get number of incoming mails.
                        SELECT COUNT(msgs.mail_id) AS total
                        FROM msgs
                        LEFT JOIN msgrcpt ON (msgs.mail_id = msgrcpt.mail_id)
                        LEFT JOIN maddr AS sender ON (msgs.sid = sender.id)
                        LEFT JOIN maddr AS recip ON (msgrcpt.rid = recip.id)
                        WHERE msgs.quar_type <> 'Q' %s
                        ''' % sql_append_where)
        total = qr[0].total or 0
    except Exception as e:
        logger.error(e)

    return total


def count_outgoing_mails(reversedDomainNames=None,
                         timeLength=None,
                         sqlAppendWhere=None):
    # timeLength is seconds.
    total = 0
    sql_append_where = ''

    if not reversedDomainNames:
        return total

    if sqlAppendWhere:
        sql_append_where = sqlAppendWhere
    else:
        sql_append_where += ' AND sender.domain IN %s' % web.sqlquote(reversedDomainNames)

    if isinstance(timeLength, int):
        _now = int(time.time())
        _length_seconds = _now - timeLength
        sql_append_where += ' AND msgs.time_num > %d' % _length_seconds

    try:
        qr_count = web.conn_amavisd.query("""
                              -- Get number of outgoing mails.
                              SELECT COUNT(msgs.mail_id) AS total
                              FROM msgs
                              RIGHT JOIN msgrcpt ON (msgs.mail_id = msgrcpt.mail_id)
                              RIGHT JOIN maddr AS sender ON (msgs.sid = sender.id)
                              RIGHT JOIN maddr AS recip ON (msgrcpt.rid = recip.id)
                              WHERE msgs.quar_type <> 'Q' %s""" % sql_append_where)
        total = qr_count[0].total or 0
    except Exception:
        pass

    return total


def count_virus_mails(reversedDomainNames=None, timeLength=None):
    # timeLength is seconds.
    total = 0
    sql_append_where = ''

    if not reversedDomainNames:
        return total

    if session.get('is_global_admin') is not True:
        sql_append_where += ' AND (sender.domain IN {} OR recip.domain IN {})'.format(
            web.sqlquote(reversedDomainNames),
            web.sqlquote(reversedDomainNames),
        )

    if isinstance(timeLength, int):
        _now = int(time.time())
        _length_seconds = _now - timeLength
        sql_append_where += ' AND msgs.time_num > %d' % _length_seconds

    try:
        qr = web.conn_amavisd.query("""
                        SELECT COUNT(msgs.mail_id) AS total
                          FROM msgs
                    RIGHT JOIN msgrcpt ON (msgs.mail_id = msgrcpt.mail_id)
                    RIGHT JOIN maddr AS sender ON (msgs.sid = sender.id)
                    RIGHT JOIN maddr AS recip ON (msgrcpt.rid = recip.id)
                         WHERE msgs.content = 'V'
                               AND msgs.quar_type='Q'
                               %s
                        """ % sql_append_where)
        total = qr[0].total or 0
    except Exception:
        pass

    return total


def count_quarantined(reversedDomainNames=None, timeLength=None):
    # timeLength is seconds.
    total = 0
    sql_append_where = ''

    if not session.get('is_global_admin'):
        sql_append_where += ' AND (sender.domain IN {} OR recip.domain IN {})'.format(
            web.sqlquote(reversedDomainNames),
            web.sqlquote(reversedDomainNames),
        )

    if isinstance(timeLength, int):
        _now = int(time.time())
        _length_seconds = _now - timeLength
        sql_append_where += ' AND msgs.time_num > %d' % _length_seconds

    try:
        if session.get('is_global_admin'):
            qr = web.conn_amavisd.query("""
                            SELECT COUNT(msgs.mail_id) AS total
                              FROM msgs
                        RIGHT JOIN maddr AS sender ON (msgs.sid = sender.id)
                             WHERE msgs.quar_type = 'Q' %s
                            """ % sql_append_where)
        else:
            qr = web.conn_amavisd.query("""
                            SELECT COUNT(msgs.mail_id) AS total
                              FROM msgs
                        RIGHT JOIN msgrcpt ON (msgs.mail_id = msgrcpt.mail_id)
                        RIGHT JOIN maddr AS sender ON (msgs.sid = sender.id)
                        RIGHT JOIN maddr AS recip ON (msgrcpt.rid = recip.id)
                             WHERE msgs.quar_type = 'Q' %s
                            """ % sql_append_where)

        total = qr[0].total or 0
    except:
        log_traceback()

    return total


def get_in_out_mails(log_type='sent',
                     cur_page=1,
                     account_type='',
                     account='',
                     page_size_limit=None):
    """
    @account_type: 'domain', 'user', None
    @log_type: 'sent', 'received', 'all'

    @return (True, {'count': <int>, 'records': <list>}
    """
    log_type = str(log_type)
    cur_page = int(cur_page)
    account_type = str(account_type) or None
    account = str(account) or None

    result = {'count': 0, 'records': []}
    count = 0          # Number of total mails.
    records = {}       # Detail records.
    sql_append_where = ''
    reversed_account = ''

    if not page_size_limit:
        page_size_limit = settings.PAGE_SIZE_LIMIT

    if account_type == 'domain':
        reversed_account = iredutils.reverse_amavisd_domain_names([account])

    # Get all managed domain names and reversed names.
    all_domains = []
    allReversedDomainNames = []
    quoted_all_reversed_domain_names = []
    sql_restricted_sender_domains = ''
    sql_restricted_recip_domains = ''
    if not session.get('account_is_mail_user'):
        if settings.backend == 'ldap':
            _qr = ldap_lib_admin.get_managed_domains(admin=session.get('username'))
            if _qr[0]:
                all_domains = _qr[1]
        elif settings.backend in ['mysql', 'pgsql']:
            qr_all_domains = sql_lib_admin.get_managed_domains(admin=session.get('username'),
                                                               domain_name_only=True)
            if qr_all_domains[0]:
                all_domains += qr_all_domains[1]
        else:
            result['count'] = count
            result['records'] = list(records)
            return True, result

        allReversedDomainNames = iredutils.reverse_amavisd_domain_names(all_domains)
        quoted_all_reversed_domain_names = web.sqlquote(allReversedDomainNames)
        sql_restricted_sender_domains = ' AND sender.domain IN %s' % quoted_all_reversed_domain_names
        sql_restricted_recip_domains = ' AND recip.domain IN %s' % quoted_all_reversed_domain_names

    # restrict permission for per-account search
    # @log_type == 'sent'
    # - if domain is under control, no restriction
    # - if domain is not under control, restrict recipient domain to managed domains
    # @log_type == 'received'
    # - if domain is under control, no restriction
    # - if domain is not under control, restrict sender domain to managed domains
    verify_domain = account
    if account_type == 'user':
        verify_domain = account.split('@', 1)[-1]

    if log_type == 'received':
        if account_type == 'domain':
            if session.get('is_global_admin') or verify_domain in all_domains:
                sql_append_where += ' AND recip.domain IN %s' % web.sqlquote(reversed_account)
            else:
                sql_append_where += ' {} AND recip.domain IN {}'.format(sql_restricted_sender_domains, web.sqlquote(reversed_account))
        elif account_type == 'user':
            if session.get('is_global_admin') or verify_domain in all_domains:
                sql_append_where += ' AND recip.email=%s' % web.sqlquote(account)
            else:
                sql_append_where += ' {} AND recip.email={}'.format(sql_restricted_sender_domains, web.sqlquote(account))
        else:
            if settings.AMAVISD_SHOW_NON_LOCAL_DOMAINS:
                if session.get('is_global_admin'):
                    pass
                else:
                    if not quoted_all_reversed_domain_names:
                        return True, result
                    else:
                        sql_append_where += ' AND recip.domain IN %s' % quoted_all_reversed_domain_names
            else:
                if not quoted_all_reversed_domain_names:
                    return True, result
                else:
                    sql_append_where += ' AND recip.domain IN %s' % quoted_all_reversed_domain_names

    elif log_type == 'sent':
        if account_type == 'domain':
            if session.get('is_global_admin') or verify_domain in all_domains:
                sql_append_where += ' AND sender.domain IN %s' % web.sqlquote(reversed_account)
            else:
                sql_append_where += ' {} AND sender.domain IN {}'.format(sql_restricted_recip_domains, web.sqlquote(reversed_account))
        elif account_type == 'user':
            if session.get('is_global_admin') or verify_domain in all_domains:
                sql_append_where += ' AND sender.email = %s' % (web.sqlquote(account))
            else:
                sql_append_where += ' {} AND sender.email = {}'.format(sql_restricted_recip_domains, web.sqlquote(account))
        else:
            if settings.AMAVISD_SHOW_NON_LOCAL_DOMAINS:
                if session.get('is_global_admin'):
                    pass
                else:
                    if not quoted_all_reversed_domain_names:
                        return True, result
                    else:
                        sql_append_where += ' AND sender.domain IN %s' % quoted_all_reversed_domain_names
            else:
                if not quoted_all_reversed_domain_names:
                    return True, result
                else:
                    sql_append_where += ' AND sender.domain IN %s' % quoted_all_reversed_domain_names

    ########################
    # Get detail records.
    #
    try:
        if log_type == 'received':
            count = count_incoming_mails(allReversedDomainNames,
                                         sqlAppendWhere=sql_append_where)

            qr = web.conn_amavisd.query(
                '''
                -- Get records of received mails.
                SELECT
                    msgs.mail_id, msgs.subject, msgs.time_num,
                    msgs.size, msgs.spam_level, msgs.client_addr, msgs.policy,
                    sender.email_raw AS sender_email,
                    recip.email_raw AS recipient
                FROM msgs
                LEFT JOIN msgrcpt ON (msgs.mail_id = msgrcpt.mail_id)
                LEFT JOIN maddr AS sender ON (msgs.sid = sender.id)
                LEFT JOIN maddr AS recip ON (msgrcpt.rid = recip.id)
                WHERE msgs.quar_type <> 'Q' %s
                ORDER BY msgs.time_num DESC
                LIMIT %d
                OFFSET %d
                ''' % (sql_append_where,
                       page_size_limit,
                       (cur_page - 1) * page_size_limit)
            )
            records = iredutils.bytes2str(qr)
        elif log_type == 'sent':
            count = count_outgoing_mails(allReversedDomainNames,
                                         sqlAppendWhere=sql_append_where)

            qr = web.conn_amavisd.query(
                '''
                -- Get records of sent mails.
                SELECT
                    msgs.mail_id, msgs.subject, msgs.time_num,
                    msgs.size, msgs.client_addr, msgs.policy,
                    sender.email_raw AS sender_email,
                    recip.email_raw AS recipient
                FROM msgs
                RIGHT JOIN msgrcpt ON (msgs.mail_id = msgrcpt.mail_id)
                RIGHT JOIN maddr AS sender ON (msgs.sid = sender.id)
                RIGHT JOIN maddr AS recip ON (msgrcpt.rid = recip.id)
                WHERE msgs.quar_type <> 'Q' %s
                ORDER BY msgs.time_num DESC
                LIMIT %d
                OFFSET %d
                ''' % (sql_append_where,
                       page_size_limit,
                       (cur_page - 1) * page_size_limit)
            )
            records = iredutils.bytes2str(qr)
        else:
            records = {}
    except:
        pass

    return True, {'count': count, 'records': list(records)}


def get_top_users(reversedDomainNames=None,
                  log_type='sent',
                  timeLength=None,
                  number=10):
    records = {}
    sql_append_where = ''

    if settings.AMAVISD_SHOW_NON_LOCAL_DOMAINS:
        if session.get('is_global_admin'):
            pass
        else:
            if not reversedDomainNames:
                return []
            else:
                if log_type == 'sent':
                    sql_append_where += ' AND sender.domain IN %s' % web.sqlquote(reversedDomainNames)
                elif log_type == 'received':
                    sql_append_where += ' AND rcpt.domain IN %s' % web.sqlquote(reversedDomainNames)
    else:
        if log_type == 'sent':
            sql_append_where += ' AND sender.domain IN %s' % web.sqlquote(reversedDomainNames)
        elif log_type == 'received':
            sql_append_where += ' AND rcpt.domain IN %s' % web.sqlquote(reversedDomainNames)

    if isinstance(timeLength, int):
        _now = int(time.time())
        _length_seconds = _now - timeLength
        sql_append_where += ' AND msgs.time_num > %d' % _length_seconds

    # `msgs.policy` (Amavisd policy bank) is used to identify account type.
    # for example, 'MLMMJ' means mlmmj mailing list.
    if log_type == 'sent':
        try:
            result = web.conn_amavisd.query(
                """
                -- Get top 10 senders.
                SELECT COUNT(msgs.mail_id) AS total,
                       sender.email_raw AS mail,
                       msgs.policy AS policy
                  FROM msgs
                 RIGHT JOIN maddr AS sender ON (msgs.sid = sender.id)
                 WHERE 1=1 %s
                 GROUP BY mail, policy
                 ORDER BY total DESC
                 LIMIT %d
                 """ % (sql_append_where, number))
            records = list(result)
        except:
            log_traceback()

    elif log_type == 'received':
        try:
            result = web.conn_amavisd.query(
                """
                -- Get top 10 recipients
                SELECT COUNT(msgs.mail_id) AS total,
                       rcpt.email_raw AS mail
                  FROM msgs
            RIGHT JOIN msgrcpt ON (msgs.mail_id = msgrcpt.mail_id)
            RIGHT JOIN maddr AS sender ON (msgs.sid = sender.id)
            RIGHT JOIN maddr AS rcpt ON (msgrcpt.rid = rcpt.id)
                 WHERE 1=1 %s
              GROUP BY mail
              ORDER BY total DESC
                 LIMIT %d
                """ % (sql_append_where, number))
            records = list(result)
        except:
            log_traceback()

    records = iredutils.bytes2str(records)
    return list(records)
