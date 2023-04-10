# Author: Zhang Huangbin <zhb@iredmail.org>

import web
from libs import iredutils
from libs.logger import log_activity
from libs.amavisd import utils

session = web.config.get('_session')


def get_wblist(account,
               whitelist=True,
               blacklist=True,
               outbound_whitelist=True,
               outbound_blacklist=True):
    """Get white/blacklists of specified account."""
    inbound_sql_where = 'users.email=$user AND users.id=wblist.rid AND wblist.sid = mailaddr.id'
    if whitelist and not blacklist:
        inbound_sql_where += ' AND wblist.wb=%s' % web.sqlquote('W')
    if not whitelist and blacklist:
        inbound_sql_where += ' AND wblist.wb=%s' % web.sqlquote('B')

    outbound_sql_where = 'users.email=$user AND users.id=outbound_wblist.sid AND outbound_wblist.rid = mailaddr.id'
    if outbound_whitelist and not outbound_blacklist:
        outbound_sql_where += ' AND outbound_wblist.wb=%s' % web.sqlquote('W')
    if not whitelist and blacklist:
        outbound_sql_where += ' AND outbound_wblist.wb=%s' % web.sqlquote('B')

    wl = []
    bl = []
    outbound_wl = []
    outbound_bl = []

    try:
        qr = web.conn_amavisd.select(
            ['mailaddr', 'users', 'wblist'],
            vars={'user': account},
            what='mailaddr.email AS address, wblist.wb AS wb',
            where=inbound_sql_where,
        )

        for r in qr:
            if r.wb == 'W':
                wl.append(iredutils.bytes2str(r.address))
            else:
                bl.append(iredutils.bytes2str(r.address))

        qr = web.conn_amavisd.select(
            ['mailaddr', 'users', 'outbound_wblist'],
            vars={'user': account},
            what='mailaddr.email AS address, outbound_wblist.wb AS wb',
            where=outbound_sql_where,
        )
        for r in qr:
            if r.wb == 'W':
                outbound_wl.append(iredutils.bytes2str(r.address))
            else:
                outbound_bl.append(iredutils.bytes2str(r.address))
    except Exception as e:
        return False, e

    wl.sort()
    bl.sort()
    outbound_wl.sort()
    outbound_bl.sort()

    return (True, {'inbound_whitelists': wl,
                   'inbound_blacklists': bl,
                   'outbound_whitelists': outbound_wl,
                   'outbound_blacklists': outbound_bl})


def add_wblist(account,
               wl_senders=None,
               bl_senders=None,
               wl_rcpts=None,
               bl_rcpts=None,
               flush_before_import=False):
    """Add white/blacklists for specified account.

    wl_senders -- whitelist senders (inbound)
    bl_senders -- blacklist senders (inbound)
    wl_rcpts -- whitelist recipients (outbound)
    bl_rcpts -- blacklist recipients (outbound)
    flush_before_import -- Delete all existing wblist before importing
                           new wblist
    """
    if not iredutils.is_valid_amavisd_address(account):
        return False, 'INVALID_ACCOUNT'

    # Remove duplicate.
    if wl_senders:
        wl_senders = {str(s).lower()
                      for s in wl_senders
                      if iredutils.is_valid_wblist_address(s)}
    else:
        wl_senders = []

    # Whitelist has higher priority, don't include whitelisted sender.
    if bl_senders:
        bl_senders = {str(s).lower()
                      for s in bl_senders
                      if iredutils.is_valid_wblist_address(s)}
    else:
        bl_senders = []

    if wl_rcpts:
        wl_rcpts = {str(s).lower()
                    for s in wl_rcpts
                    if iredutils.is_valid_wblist_address(s)}
    else:
        wl_rcpts = []

    if bl_rcpts:
        bl_rcpts = {str(s).lower()
                    for s in bl_rcpts
                    if iredutils.is_valid_wblist_address(s)}
    else:
        bl_rcpts = []

    if flush_before_import:
        if wl_senders:
            bl_senders = {s for s in bl_senders if s not in wl_senders}

        if wl_rcpts:
            bl_rcpts = {s for s in bl_rcpts if s not in wl_rcpts}

    sender_addresses = set(wl_senders) | set(bl_senders)
    rcpt_addresses = set(wl_rcpts) | set(bl_rcpts)
    all_addresses = list(sender_addresses | rcpt_addresses)

    # Get current user's id from `amavisd.users`
    qr = utils.get_user_record(account=account)

    if qr[0]:
        user_id = qr[1].id
    else:
        return qr

    # Delete old records
    if flush_before_import:
        # user_id = wblist.rid
        web.conn_amavisd.delete(
            'wblist',
            vars={'rid': user_id},
            where='rid=$rid',
        )

        # user_id = outbound_wblist.sid
        web.conn_amavisd.delete(
            'outbound_wblist',
            vars={'sid': user_id},
            where='sid=$sid',
        )

    if not all_addresses:
        return True,

    # Insert all senders into `amavisd.mailaddr`
    utils.create_mailaddr(addresses=all_addresses)

    # Get `mailaddr.id` of senders
    sender_records = {}
    if sender_addresses:
        qr = web.conn_amavisd.select(
            'mailaddr',
            vars={'addresses': list(sender_addresses)},
            what='id, email',
            where='email IN $addresses',
        )

        for r in qr:
            sender_records[iredutils.bytes2str(r.email)] = r.id
        del qr

    # Get `mailaddr.id` of recipients
    rcpt_records = {}
    if rcpt_addresses:
        qr = web.conn_amavisd.select(
            'mailaddr',
            vars={'addresses': list(rcpt_addresses)},
            what='id, email',
            where='email IN $addresses',
        )

        for r in qr:
            rcpt_records[iredutils.bytes2str(r.email)] = r.id

        del qr

    # Remove existing records of current submitted records before inserting new.
    try:
        if sender_records:
            web.conn_amavisd.delete(
                'wblist',
                vars={'rid': user_id, 'sid': list(sender_records.values())},
                where='rid=$rid AND sid IN $sid',
            )

        if rcpt_records:
            web.conn_amavisd.delete(
                'outbound_wblist',
                vars={'sid': user_id, 'rid': list(rcpt_records.values())},
                where='sid=$sid AND rid IN $rid',
            )
    except Exception as e:
        return False, repr(e)

    # Generate dict used to build SQL statements for importing wblist
    values = []
    if sender_addresses:
        for s in wl_senders:
            if sender_records.get(s):
                values.append({'rid': user_id, 'sid': sender_records[s], 'wb': 'W'})

        for s in bl_senders:
            # Filter out same record in blacklist
            if sender_records.get(s) and s not in wl_senders:
                values.append({'rid': user_id, 'sid': sender_records[s], 'wb': 'B'})

    rcpt_values = []
    if rcpt_addresses:
        for s in wl_rcpts:
            if rcpt_records.get(s):
                rcpt_values.append({'sid': user_id, 'rid': rcpt_records[s], 'wb': 'W'})

        for s in bl_rcpts:
            # Filter out same record in blacklist
            if rcpt_records.get(s) and s not in wl_rcpts:
                rcpt_values.append({'sid': user_id, 'rid': rcpt_records[s], 'wb': 'B'})

    try:
        if values:
            web.conn_amavisd.multiple_insert('wblist', values)

        if rcpt_values:
            web.conn_amavisd.multiple_insert('outbound_wblist', rcpt_values)

        # Log
        if values:
            if flush_before_import:
                log_activity(msg='Update whitelists and/or blacklists for %s.' % account,
                             admin=session['username'],
                             event='update_wblist')
            else:
                if wl_senders:
                    log_activity(msg='Add whitelists for {}: {}.'.format(account, ', '.join(wl_senders)),
                                 admin=session['username'],
                                 event='update_wblist')

                if bl_senders:
                    log_activity(msg='Add blacklists for {}: {}.'.format(account, ', '.join(bl_senders)),
                                 admin=session['username'],
                                 event='update_wblist')

        if rcpt_values:
            if flush_before_import:
                log_activity(msg='Update outbound whitelists and/or blacklists for %s.' % account,
                             admin=session['username'],
                             event='update_wblist')
            else:
                if wl_rcpts:
                    log_activity(msg='Add outbound whitelists for {}: {}.'.format(account, ', '.join(wl_senders)),
                                 admin=session['username'],
                                 event='update_wblist')

                if bl_rcpts:
                    log_activity(msg='Add outbound blacklists for {}: {}.'.format(account, ', '.join(bl_senders)),
                                 admin=session['username'],
                                 event='update_wblist')

    except Exception as e:
        return False, repr(e)

    return True,


def delete_wblist(account,
                  wl_senders=None,
                  bl_senders=None,
                  wl_rcpts=None,
                  bl_rcpts=None):
    if not iredutils.is_valid_amavisd_address(account):
        return False, 'INVALID_ACCOUNT'

    # Remove duplicate.
    if wl_senders:
        wl_senders = list({str(s).lower()
                           for s in wl_senders
                           if iredutils.is_valid_wblist_address(s)})

    # Whitelist has higher priority, don't include whitelisted sender.
    if bl_senders:
        bl_senders = list({str(s).lower()
                           for s in bl_senders
                           if iredutils.is_valid_wblist_address(s)})

    if wl_rcpts:
        wl_rcpts = list({str(s).lower()
                         for s in wl_rcpts
                         if iredutils.is_valid_wblist_address(s)})

    if bl_rcpts:
        bl_rcpts = list({str(s).lower()
                         for s in bl_rcpts
                         if iredutils.is_valid_wblist_address(s)})

    # Get account id from `amavisd.users`
    qr = utils.get_user_record(account=account)

    if qr[0]:
        user_id = qr[1].id
    else:
        return qr

    # Remove wblist.
    # No need to remove unused senders in `mailaddr` table, because we
    # have daily cron job to delete them (tools/cleanup_amavisd_db.py).
    try:
        # Get `mailaddr.id` for wblist senders
        if wl_senders:
            sids = []
            qr = web.conn_amavisd.select(
                'mailaddr',
                vars={'addresses': wl_senders},
                what='id',
                where='email IN $addresses',
            )

            for r in qr:
                sids.append(r.id)

            if sids:
                web.conn_amavisd.delete(
                    'wblist',
                    vars={'user_id': user_id, 'sids': sids},
                    where="rid=$user_id AND sid IN $sids AND wb='W'",
                )

        if bl_senders:
            sids = []
            qr = web.conn_amavisd.select(
                'mailaddr',
                vars={'addresses': bl_senders},
                what='id',
                where='email IN $addresses',
            )

            for r in qr:
                sids.append(r.id)

            if sids:
                web.conn_amavisd.delete(
                    'wblist',
                    vars={'user_id': user_id, 'sids': sids},
                    where="rid=$user_id AND sid IN $sids AND wb='B'",
                )

        if wl_rcpts:
            rids = []
            qr = web.conn_amavisd.select(
                'mailaddr',
                vars={'addresses': wl_rcpts},
                what='id',
                where='email IN $addresses',
            )

            for r in qr:
                rids.append(r.id)

            if rids:
                web.conn_amavisd.delete(
                    'outbound_wblist',
                    vars={'user_id': user_id, 'rids': rids},
                    where="sid=$user_id AND rid IN $rids AND wb='W'",
                )

        if bl_rcpts:
            rids = []
            qr = web.conn_amavisd.select(
                'mailaddr',
                vars={'addresses': bl_rcpts},
                what='id',
                where='email IN $addresses',
            )

            for r in qr:
                rids.append(r.id)

            if rids:
                web.conn_amavisd.delete(
                    'outbound_wblist',
                    vars={'user_id': user_id, 'rids': rids},
                    where="sid=$user_id AND rid IN $rids AND wb='B'",
                )

    except Exception as e:
        return False, repr(e)

    return True,


def delete_all_wblist(account,
                      wl_senders=False,
                      bl_senders=False,
                      wl_rcpts=False,
                      bl_rcpts=False):
    if not iredutils.is_valid_amavisd_address(account):
        return False, 'INVALID_ACCOUNT'

    # Get account id from `amavisd.users`
    qr = utils.get_user_record(account=account)

    if qr[0]:
        user_id = qr[1].id
    else:
        return qr

    # Remove ALL wblist.
    # No need to remove unused senders in `mailaddr` table, because we
    # have daily cron job to delete them (tools/cleanup_amavisd_db.py).
    try:
        if wl_senders:
            web.conn_amavisd.delete(
                'wblist',
                vars={'user_id': user_id},
                where="rid=$user_id AND wb='W'",
            )

        if bl_senders:
            web.conn_amavisd.delete(
                'wblist',
                vars={'user_id': user_id},
                where="rid=$user_id AND wb='B'",
            )

        if wl_rcpts:
            web.conn_amavisd.delete(
                'outbound_wblist',
                vars={'user_id': user_id},
                where="sid=$user_id AND wb='W'",
            )

        if bl_rcpts:
            web.conn_amavisd.delete(
                'outbound_wblist',
                vars={'user_id': user_id},
                where="sid=$user_id AND wb='B'",
            )

    except Exception as e:
        return False, repr(e)

    return True,
