# Author: Zhang Huangbin <zhb@iredmail.org>

import web
import settings
from controllers import decorators
from libs import iredutils
from libs.mailparser import parse_raw_message
from libs.amavisd import QUARANTINE_TYPES
from libs.amavisd import log as lib_log
from libs.amavisd import quarantine as lib_quarantine
from libs.amavisd import wblist as lib_wblist

session = web.config.get('_session')


DELETE_ACTION_MSGS = {
    'release': 'RELEASED',
    'release_whitelist_sender': 'RELEASED_WL_SENDER',
    'release_whitelist_sender_domain': 'RELEASED_WL_SENDER_DOMAIN',
    'release_whitelist_sender_subdomain': 'RELEASED_WL_SENDER_SUBDOMAIN',
    'delete': 'DELETED',
    'deleteAll': 'DELETED',
    # log_type == 'received'
    'delete_whitelist_sender': 'DELETED_WL_SENDER',
    'delete_whitelist_sender_domain': 'DELETED_WL_SENDER_DOMAIN',
    'delete_whitelist_sender_subdomain': 'DELETED_WL_SENDER_SUBDOMAIN',
    'delete_blacklist_sender': 'DELETED_BL_SENDER',
    'delete_blacklist_sender_domain': 'DELETED_BL_SENDER_DOMAIN',
    'delete_blacklist_sender_subdomain': 'DELETED_BL_SENDER_SUBDOMAIN',
    # log_type == 'sent'
    'delete_whitelist_rcpt': 'DELETED_WL_RCPT',
    'delete_whitelist_rcpt_domain': 'DELETED_WL_RCPT_DOMAIN',
    'delete_whitelist_rcpt_subdomain': 'DELETED_WL_RCPT_SUBDOMAIN',
    'delete_blacklist_rcpt': 'DELETED_BL_RCPT',
    'delete_blacklist_rcpt_domain': 'DELETED_BL_RCPT_DOMAIN',
    'delete_blacklist_rcpt_subdomain': 'DELETED_BL_RCPT_SUBDOMAIN',
}


class InOutMails:
    @decorators.require_permission_in_session(perm='disable_viewing_mail_log', not_present=True)
    @decorators.require_admin_login
    def GET(self, log_type='sent', page=1):
        log_type = str(log_type)

        # Get current page.
        page = int(page) or 1

        qr = lib_log.get_in_out_mails(log_type=log_type, cur_page=page)
        if qr[0]:
            total = qr[1]['count']
            records = qr[1]['records']
        else:
            raise web.seeother('/domains?msg=%s' % web.urlquote(qr[1]))

        return web.render(
            'amavisd/inout.html',
            log_type=log_type,
            cur_page=page,
            account_type=None,
            account=None,
            total=total,
            records=records,
            removeLogsInDays=settings.AMAVISD_REMOVE_MAILLOG_IN_DAYS,
            msg=web.input().get('msg'),
        )

    @decorators.csrf_protected
    @decorators.require_permission_in_session(perm='disable_viewing_mail_log', not_present=True)
    @decorators.require_admin_login
    def POST(self, log_type='sent', page=1):
        # Get current page.
        page = int(page) or 1
        redirect_url = '/activities/%s/page/%d' % (log_type, page)

        form = web.input(record=[], _unicode=False)
        action = form.get('action', 'delete')

        if not action.startswith('delete'):
            raise web.seeother(redirect_url + '?msg=INVALID_ACTION')

        mailids = []
        addresses = []
        for r in form.get('record', []):
            # record format: mail_id + \r\n + sender
            tmp = r.split(r'\r\n')
            if len(tmp) == 2:
                (mid, addr) = tmp
                mailids.append(mid)

                if iredutils.is_email(addr):
                    if action.endswith('_sender') or action.endswith('_rcpt'):
                        addresses.append(addr)
                    elif action.endswith('_domain'):
                        addresses.append('@' + addr.split('@', 1)[-1])
                    elif action.endswith('_subdomain'):
                        addresses.append('@.' + addr.split('@', 1)[-1])

        if (not mailids) and (action != 'deleteAll'):
            raise web.seeother(redirect_url + '?msg=INVALID_MAILID')

        if action == 'deleteAll':
            qr_del = lib_log.delete_all_records(log_type=log_type, account=None)
        else:
            # delete records by mailids
            qr_del = lib_log.delete_records_by_mail_id(log_type=log_type, mail_ids=mailids)

        if not qr_del[0]:
            raise web.seeother(redirect_url + '?msg=' + web.urlquote(qr_del[1]))

        # Add server-wide white/blacklists.
        # Note: if admin is a normal admin, we don't know which domain he
        #       manages, so cannot add per-domain white/blacklists here.
        if session.get('is_global_admin') and addresses:
            wblist_account = '@.'

            # whitelist recipients
            if action.startswith('delete_whitelist'):
                qr_wblist = lib_wblist.add_wblist(account=wblist_account, wl_senders=addresses)

            elif action.startswith('delete_blacklist'):
                qr_wblist = lib_wblist.add_wblist(account=wblist_account, bl_senders=addresses)
            else:
                qr_wblist = (False, 'INVALID_ACTION')

            if not qr_wblist[0]:
                raise web.seeother(redirect_url + '?msg=' + web.urlquote(qr_wblist[1]))

        raise web.seeother(redirect_url + '?msg=' + DELETE_ACTION_MSGS[action])


class InOutMailsPerAccount:
    @decorators.require_permission_in_session(perm='disable_viewing_mail_log', not_present=True)
    @decorators.require_login
    def GET(self, log_type, account_type, account, page=1):
        log_type = str(log_type)
        account_type = str(account_type)
        account = str(account)
        page = int(page) or 1

        # Verify account syntax
        if account_type == 'domain':
            if not iredutils.is_domain(account):
                raise web.seeother('/activities/%s?msg=INVALID_DOMAIN_NAME' % log_type)
        elif account_type == 'user':
            if not iredutils.is_email(account):
                raise web.seeother('/activities/%s?msg=INVALID_MAIL' % log_type)

        qr = lib_log.get_in_out_mails(log_type=log_type,
                                      cur_page=page,
                                      account_type=account_type,
                                      account=account)

        if qr[0]:
            total = qr[1]['count']
            records = qr[1]['records']
        else:
            raise web.seeother('/activities/{}?msg={}'.format(log_type, web.urlquote(qr[1])))

        return web.render(
            'amavisd/inout.html',
            log_type=log_type,
            cur_page=page,
            account_type=account_type,
            account=account,
            total=total,
            records=records,
            removeLogsInDays=settings.AMAVISD_REMOVE_MAILLOG_IN_DAYS,
            msg=web.input().get('msg'),
        )

    @decorators.csrf_protected
    @decorators.require_permission_in_session(perm='disable_viewing_mail_log', not_present=True)
    @decorators.require_login
    def POST(self, log_type, account_type, account, page=1):
        log_type = str(log_type).lower()
        account_type = str(account_type).lower()
        account = str(account).lower()
        page = int(page) or 1
        redirect_url = '/activities/{}/{}/{}/page/{}'.format(log_type, account_type, account, page)

        form = web.input(record=[], _unicode=False)
        action = str(form.get('action', ''))

        if not action.startswith('delete'):
            raise web.seeother(redirect_url + '?msg=INVALID_ACTION')

        mailids = []
        addresses = []
        for r in form.get('record', []):
            # record format: mail_id + \r\n + sender
            tmp = r.split(r'\r\n')
            if len(tmp) == 2:
                (mid, addr) = tmp
                mailids.append(mid)

                if iredutils.is_email(addr):
                    if action.endswith('_sender') or action.endswith('_rcpt'):
                        addresses.append(addr)
                    elif action.endswith('_domain'):
                        addresses.append('@' + addr.split('@', 1)[-1])
                    elif action.endswith('_subdomain'):
                        addresses.append('@.' + addr.split('@', 1)[-1])

        if (not mailids) and (action != 'deleteAll'):
            raise web.seeother(redirect_url + '?msg=INVALID_MAILID')

        if action == 'deleteAll':
            qr_del = lib_log.delete_all_records(log_type=log_type, account=account)
        else:
            # delete records by mailids
            qr_del = lib_log.delete_records_by_mail_id(log_type=log_type, mail_ids=mailids)

        if not qr_del[0]:
            raise web.seeother(redirect_url + '?msg=' + web.urlquote(qr_del[1]))

        # Add server-wide white/blacklists.
        # Note: if admin is a normal admin, we don't know which domain he
        #       manages, so cannot add per-domain white/blacklists here.
        if addresses and \
           (action.startswith('delete_whitelist') or action.startswith('delete_blacklist')):
            wblist_account = None
            _do_wb = False
            if session.get('is_global_admin'):
                # Global wblist
                wblist_account = account
                _do_wb = True
            elif session.get('account_is_mail_user'):
                # per-account wblist
                wblist_account = session['username']
                _do_wb = True

            if _do_wb:
                # whitelist recipients
                if action.startswith('delete_whitelist'):
                    qr_wblist = lib_wblist.add_wblist(account=wblist_account, wl_senders=addresses)

                elif action.startswith('delete_blacklist'):
                    qr_wblist = lib_wblist.add_wblist(account=wblist_account, bl_senders=addresses)
                else:
                    qr_wblist = (False, 'INVALID_ACTION')

                if not qr_wblist[0]:
                    raise web.seeother(redirect_url + '?msg=' + web.urlquote(qr_wblist[1]))

        raise web.seeother(redirect_url + '?msg=' + DELETE_ACTION_MSGS[action])


class QuarantinedMails:
    @decorators.require_permission_in_session(perm='disable_managing_quarantined_mails', not_present=True)
    @decorators.require_admin_login
    def GET(self, quarantined_type=None, page=1):
        form = web.input()
        sort_by_score = 'sort_by_score' in form

        # Get current page.
        # None means on page 1, e.g. /activities/quarantined
        if quarantined_type in QUARANTINE_TYPES or quarantined_type is None:
            page = int(page) or 1
        else:
            page = int(quarantined_type) or 1
            quarantined_type = None

        qr = lib_quarantine.get_quarantined_mails(quarantined_type=quarantined_type,
                                                  page=page,
                                                  sort_by_score=sort_by_score)

        if qr[0]:
            (total, records) = qr[1]
        else:
            raise web.seeother('/domains?msg=%s' % web.urlquote(qr[1]))

        return web.render(
            'amavisd/quarantined.html',
            account_type=None,
            account=None,
            quarantined_type=quarantined_type,
            cur_page=page,
            total=total,
            records=records,
            removeQuarantinedInDays=settings.AMAVISD_REMOVE_QUARANTINED_IN_DAYS,
            sort_by_score=sort_by_score,
            msg=form.get('msg'),
        )

    @decorators.csrf_protected
    @decorators.require_permission_in_session(perm='disable_managing_quarantined_mails', not_present=True)
    @decorators.require_admin_login
    def POST(self, quarantined_type=None, page=1):
        form = web.input(record=[], _unicode=False)
        action = form.get('action', None)

        if quarantined_type not in QUARANTINE_TYPES:
            quarantined_type = None

        redirect_url = '/activities/quarantined'
        if quarantined_type:
            redirect_url = redirect_url + '/' + quarantined_type

        redirect_url += '/page/{}'.format(page)

        if action == 'deleteAll':
            if session.get('is_global_admin'):
                lib_quarantine.delete_all_quarantined(quarantined_type=quarantined_type)

            raise web.seeother(redirect_url + '?msg=%s' % DELETE_ACTION_MSGS[action])

        # Get necessary information from web form.
        records = []
        mailids = []
        senders = set()

        for r in form.get('record', []):
            # record format: mail_id + \r\n + secret_id + \r\n + sender
            tmp = r.split(r'\r\n')
            if len(tmp) == 3:
                records += [{'mail_id': tmp[0], 'secret_id': tmp[1]}]
                mailids.append(tmp[0])

                if iredutils.is_email(tmp[2]):
                    senders.add(tmp[2])

        if not mailids:
            if not (action == 'deleteAll' and session.get('is_global_admin')):
                raise web.seeother(redirect_url + '?msg=INVALID_MAILID')

        if action != 'deleteAll' and not mailids:
            raise web.seeother(redirect_url + '?msg=%s' % DELETE_ACTION_MSGS[action])

        wb_senders = set()
        if action in ['release_whitelist_sender', 'delete_blacklist_sender']:
            wb_senders = senders
        elif action in ['release_whitelist_sender_domain', 'delete_blacklist_sender_domain']:
            for s in senders:
                wb_senders.add('@' + s.split('@', 1)[-1])
        elif action in ['release_whitelist_sender_subdomain', 'delete_blacklist_sender_subdomain']:
            for s in senders:
                wb_senders.add('@.' + s.split('@', 1)[-1])

        wblist_account = '@.'
        if session.get('is_global_admin'):
            # Add as global wblist
            wblist_account = '@.'
        elif session.get('is_normal_admin'):
            # Add as per-domain wblist
            wblist_account = '@' + session['username'].split('@', 1)[-1]

        if action.startswith('release'):
            result = lib_quarantine.release_quarantined_mails(records=records)

            if action in ['release_whitelist_sender',
                          'release_whitelist_sender_domain',
                          'release_whitelist_sender_subdomain']:
                # whitelist senders or sender_domains
                if wb_senders:
                    qr = lib_wblist.add_wblist(account=wblist_account, wl_senders=wb_senders)

                    if not qr[0]:
                        result = qr

        elif action.startswith('delete'):
            result = lib_log.delete_records_by_mail_id(log_type='quarantine', mail_ids=mailids)

            if action in ['delete_blacklist_sender',
                          'delete_blacklist_sender_domain',
                          'delete_blacklist_sender_subdomain']:
                if wb_senders:
                    qr = lib_wblist.add_wblist(account=wblist_account, bl_senders=wb_senders)
                    if not qr[0]:
                        result = qr

        else:
            result = (False, 'INVALID_ACTION')

        if result[0]:
            raise web.seeother(redirect_url + '?msg=%s' % DELETE_ACTION_MSGS[action])
        else:
            raise web.seeother(redirect_url + '?msg=%s' % web.urlquote(result[1]))


class QuarantinedMailsPerAccount:
    @decorators.require_permission_in_session(perm='disable_managing_quarantined_mails', not_present=True)
    @decorators.require_login
    def GET(self, account_type, account, quarantined_type=None, page=1):
        account_type = str(account_type)
        account = str(account)

        form = web.input()
        sort_by_score = 'sort_by_score' in form

        # Normal user login
        if session['account_is_mail_user'] and account_type == 'user':
            if session['username'] != account:
                # Accessing other's quarantined mails
                raise web.seeother('/activities/quarantined/user/%s?msg=PERMISSION_DENIED' % session['username'])
            if 'quarantine' in session.get('disabled_user_preferences', []):
                raise web.seeother('/preferences?msg=PERMISSION_DENIED')

        if quarantined_type:
            # Get current page.
            if str(quarantined_type).isdigit():
                # According to URL mapping, quarantined_type could be page number.
                page = int(quarantined_type) or 1
            else:
                page = int(page) or 1

            if quarantined_type not in QUARANTINE_TYPES:
                quarantined_type = None

        qr = lib_quarantine.get_quarantined_mails(account_type=account_type,
                                                  account=account,
                                                  quarantined_type=quarantined_type,
                                                  page=page,
                                                  sort_by_score=sort_by_score)

        if qr[0]:
            (total, records) = qr[1]
        else:
            if session['account_is_mail_user']:
                raise web.seeother('/preferences?msg=%s' % web.urlquote(qr[1]))
            else:
                raise web.seeother('/domains?msg=%s' % web.urlquote(qr[1]))

        template_file = 'amavisd/quarantined.html'
        if session['account_is_mail_user']:
            template_file = 'amavisd/quarantined_user.html'

        return web.render(
            template_file,
            account_type=account_type,
            account=account,
            quarantined_type=quarantined_type,
            cur_page=page,
            total=total,
            records=records,
            removeQuarantinedInDays=settings.AMAVISD_REMOVE_QUARANTINED_IN_DAYS,
            sort_by_score=sort_by_score,
            msg=form.get('msg'),
        )

    @decorators.csrf_protected
    @decorators.require_permission_in_session(perm='disable_managing_quarantined_mails', not_present=True)
    @decorators.require_login
    def POST(self, account_type, account, quarantined_type=None, page=1):
        form = web.input(record=[], _unicode=False)

        if quarantined_type:
            # Get current page.
            if str(quarantined_type).isdigit():
                # According to URL mapping, quarantined_type could be page number.
                page = int(quarantined_type) or 1
            else:
                page = int(page) or 1

            if quarantined_type not in QUARANTINE_TYPES:
                quarantined_type = None

        redirect_url = '/activities/quarantined'
        if account_type and account:
            redirect_url = redirect_url + '/{}/{}'.format(account_type, account)

        if quarantined_type:
            redirect_url = redirect_url + '/' + quarantined_type

        redirect_url += '/page/{}'.format(page)
        action = form.get('action', None)

        # Get necessary information from web form.
        records = []
        mailids = []
        senders = set()

        # Get `msgs.mail_id` and `msgs.secret_id`
        for r in form.get('record', []):
            # record format: mail_id + \r\n + secret_id + \r\n + sender
            tmp = r.split(r'\r\n')
            if len(tmp) == 3:
                records += [{'mail_id': tmp[0], 'secret_id': tmp[1]}]
                mailids.append(tmp[0])

                if iredutils.is_email(tmp[2]):
                    senders.add(tmp[2])

        if not mailids:
            raise web.seeother(redirect_url + '?msg=INVALID_MAILID')

        wb_senders = set()
        if action in ['release_whitelist_sender', 'delete_blacklist_sender']:
            wb_senders = senders
        elif action in ['release_whitelist_sender_domain', 'delete_blacklist_sender_domain']:
            for s in senders:
                wb_senders.add('@' + s.split('@', 1)[-1])
        elif action in ['release_whitelist_sender_subdomain', 'delete_blacklist_sender_subdomain']:
            for s in senders:
                wb_senders.add('@.' + s.split('@', 1)[-1])

        wblist_account = account
        if session.get('is_global_admin'):
            # Add as global wblist
            wblist_account = '@.'
        elif session.get('is_normal_admin'):
            # Add as per-domain wblist
            wblist_account = '@' + account.split('@', 1)[-1]

        if action.startswith('release'):
            result = lib_quarantine.release_quarantined_mails(records=records)

            if action in ['release_whitelist_sender',
                          'release_whitelist_sender_domain',
                          'release_whitelist_sender_subdomain']:
                # whitelist senders or sender_domains
                if wb_senders:
                    qr = lib_wblist.add_wblist(account=wblist_account, wl_senders=wb_senders)

                    if not qr[0]:
                        result = qr
        elif action.startswith('delete'):
            result = lib_log.delete_records_by_mail_id(log_type='quarantine', mail_ids=mailids)

            if action in ['delete_blacklist_sender',
                          'delete_blacklist_sender_domain',
                          'delete_blacklist_sender_subdomain']:
                # Don't add account domain in blacklist
                try:
                    wb_senders.remove(account.split('@', 1)[-1])
                except:
                    pass

                if wb_senders:
                    qr = lib_wblist.add_wblist(account=wblist_account, bl_senders=wb_senders)
                    if not qr[0]:
                        result = qr
        else:
            result = (False, 'INVALID_ACTION')

        if result[0]:
            msg = DELETE_ACTION_MSGS[action]
        else:
            msg = web.urlquote(result[1])

        raise web.seeother(redirect_url + '?msg=%s' % msg)


class GetRawMessageOfQuarantinedMail:
    @decorators.require_login
    def GET(self, mail_id):
        qr = lib_quarantine.get_raw_message(mail_id=mail_id)

        if not qr[0]:
            raise web.seeother('/activities/quarantined?msg=%s' % web.urlquote(qr[1]))

        # Parse mail and convert to HTML.
        try:
            (headers, bodies, attachments) = parse_raw_message(qr[1])
        except Exception as e:
            raise web.seeother('/activities/quarantined?msg=%s' % web.urlquote(repr(e)))

        return web.render('amavisd/quarantined_raw.html',
                          mail_id=mail_id,
                          headers=headers,
                          bodies=bodies,
                          attachments=attachments)


class SearchLog:
    @decorators.require_admin_login
    def GET(self):
        raise web.seeother('/activities/sent')

    @decorators.csrf_protected
    @decorators.require_admin_login
    def POST(self):
        form = web.input(_unicode=False)
        account = form.get('account', '')

        log_type = 'sent'
        if 'received' in form:
            log_type = 'received'
        elif 'sent' in form:
            log_type = 'sent'
        elif 'quarantined' in form:
            log_type = 'quarantined'

        if iredutils.is_email(account):
            account_type = 'user'
        elif iredutils.is_domain(account):
            account_type = 'domain'
        else:
            raise web.seeother('/activities/%s?msg=INVALID_ACCOUNT' % log_type)

        raise web.seeother('/activities/{}/{}/{}'.format(log_type, account_type, account))
