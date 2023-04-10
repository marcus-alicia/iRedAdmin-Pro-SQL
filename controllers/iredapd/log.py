# Author: Zhang Huangbin <zhb@iredmail.org>

from typing import List
import web
import settings

from libs.iredapd import log as iredapd_log, wblist_senderscore
from libs.iredapd import greylist as lib_greylist


if settings.backend == 'ldap':
    from libs.ldaplib import decorators
else:
    from libs.sqllib import decorators


session = web.config.get('_session')


def _filter_whitelisted_senderscore_ips(rows=None) -> List:
    # Get IP addresses of rejected sessions due to senderscore.
    whitelisted_ips = []

    try:
        _rejected_ips = [
            row.client_address
            for row in rows
            if row.action == 'REJECT'
            and row.reason.startswith('Server IP address has bad reputation')
        ]

        if _rejected_ips:
            _qr = wblist_senderscore.filter_whitelisted_ips(ips=_rejected_ips)
            if _qr[0]:
                whitelisted_ips = _qr[1]
    except:
        pass

    return whitelisted_ips


def _filter_whitelisted_greylisting_ips(rows=None):
    # Get IP addresses of rejected sessions due to greylisting.
    whitelisted_ips = []
    if not rows:
        return whitelisted_ips

    try:
        _rejected_ips = [
            row.client_address
            for row in rows
            if row.action == '451'
            and row.reason == '4.7.1 Intentional policy rejection, please try again later'
        ]

        if _rejected_ips:
            _qr = lib_greylist.filter_whitelisted_ips(ips=_rejected_ips)
            if _qr[0]:
                whitelisted_ips = _qr[1]
    except:
        pass

    return whitelisted_ips


class SMTPSessions:
    @decorators.require_admin_login
    def GET(self, page=1, outbound_only=False, rejected_only=False):
        """Display log of SMTP rejections."""
        page = int(page)
        if page < 1:
            page = 1

        qr = iredapd_log.get_log_smtp_sessions(
            outbound_only=outbound_only,
            rejected_only=rejected_only,
            offset=settings.PAGE_SIZE_LIMIT * (page - 1),
            limit=settings.PAGE_SIZE_LIMIT,
        )

        total = qr['total']
        rows = qr['rows']

        if outbound_only:
            tmpl = 'smtp_outbound_sessions.html'
        else:
            tmpl = 'smtp_sessions.html'

        num_insecure_outbound = 0
        insecure_outbound_usernames = []
        query_insecure_outbound_hours = settings.IREDAPD_QUERY_INSECURE_OUTBOUND_IN_HOURS
        if outbound_only:
            # Count insecure outbound connections.
            _qr = iredapd_log.get_smtp_insecure_outbound(hours=query_insecure_outbound_hours)
            if _qr[0]:
                num_insecure_outbound = _qr[1]['total']
                insecure_outbound_usernames = _qr[1]['usernames']

        # Get IP addresses of rejected sessions due to senderscore.
        whitelisted_senderscore_ips = []
        if session.get('is_global_admin') and total > 0:
            whitelisted_senderscore_ips = _filter_whitelisted_senderscore_ips(rows=rows)

        # Get IP addresses of rejected sessions due to greylisting.
        whitelisted_greylisting_ips = []
        if session.get('is_global_admin') and total > 0:
            whitelisted_greylisting_ips = _filter_whitelisted_greylisting_ips(rows=rows)

        return web.render('iredapd/activities/' + tmpl,
                          total=total,
                          rows=rows,
                          current_page=page,
                          rejected_only=rejected_only,
                          whitelisted_senderscore_ips=whitelisted_senderscore_ips,
                          whitelisted_greylisting_ips=whitelisted_greylisting_ips,
                          query_insecure_outbound_hours=query_insecure_outbound_hours,
                          num_insecure_outbound=num_insecure_outbound,
                          insecure_outbound_usernames=insecure_outbound_usernames,
                          msg=web.input().get('msg'))


class SMTPSessionsPerAccount:
    @decorators.require_admin_login
    def GET(self, account_type, account, page=1, outbound_only=False):
        """Display log of SMTP authentications."""
        account_type = account_type.lower()
        account = account.lower()
        page = int(page)

        if page < 1:
            page = 1

        domains = []
        sasl_usernames = []
        senders = []
        recipients = []
        client_addresses = []
        encryption_protocols = []

        # Make sure admin has privilege to manage this domain.
        if account_type == 'sasl_username':
            sasl_usernames = [account]
        elif account_type == 'sender':
            senders = [account]
        elif account_type == 'recipient':
            recipients = [account]
        elif account_type == 'domain':
            domains = [account]
        elif account_type == 'client_address':
            client_addresses = [account]
        elif account_type == 'encryption_protocol':
            encryption_protocols = [account]

        qr = iredapd_log.get_log_smtp_sessions(
            domains=domains,
            sasl_usernames=sasl_usernames,
            senders=senders,
            recipients=recipients,
            encryption_protocols=encryption_protocols,
            client_addresses=client_addresses,
            outbound_only=outbound_only,
            offset=settings.PAGE_SIZE_LIMIT * (page - 1),
            limit=settings.PAGE_SIZE_LIMIT,
        )
        total = qr['total'] or 0
        rows = qr['rows']

        if outbound_only:
            tmpl = 'smtp_outbound_sessions.html'
        else:
            tmpl = 'smtp_sessions.html'

        # Get IP addresses of rejected sessions due to senderscore.
        whitelisted_senderscore_ips = []
        if session.get('is_global_admin') and total > 0:
            whitelisted_senderscore_ips = _filter_whitelisted_senderscore_ips(rows=rows)

        # Get IP addresses of rejected sessions due to greylisting.
        whitelisted_greylisting_ips = []
        if session.get('is_global_admin') and total > 0:
            whitelisted_greylisting_ips = _filter_whitelisted_greylisting_ips(rows=rows)

        return web.render(
            'iredapd/activities/' + tmpl,
            account_type=account_type,
            account=account,
            total=total,
            rows=rows,
            whitelisted_senderscore_ips=whitelisted_senderscore_ips,
            whitelisted_greylisting_ips=whitelisted_greylisting_ips,
            current_page=page,
            msg=web.input().get('msg'),
        )


class SMTPSessionsRejected:
    @decorators.require_admin_login
    def GET(self, page=1):
        c = SMTPSessions()
        return c.GET(page=page, rejected_only=True)


class SMTPSessionsOutbound:
    @decorators.require_admin_login
    def GET(self, page=1):
        c = SMTPSessions()
        return c.GET(page=page, outbound_only=True)


class SMTPSessionsOutboundPerAccount:
    @decorators.require_admin_login
    def GET(self, account_type, account, page=1):
        c = SMTPSessionsPerAccount()
        return c.GET(account_type=account_type,
                     account=account,
                     page=page,
                     outbound_only=True)
