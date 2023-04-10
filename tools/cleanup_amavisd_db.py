#!/usr/bin/env python3

# Author: Zhang Huangbin <zhb@iredmail.org>
# Purpose: Remove old records in Amavisd database.

# USAGE:
#
#   1: Make sure you have correct database settings in iRedAdmin config file
#      'settings.py' for Amavisd.
#
#   2: Make sure you have proper values for below two parameters:
#
#       AMAVISD_REMOVE_MAILLOG_IN_DAYS = 7
#       AMAVISD_REMOVE_QUARANTINED_IN_DAYS = 7
#
#      Default values is defined in libs/default_settings.py, you can override
#      them in settings.py. WARNING: DO NOT MODIFY libs/default_settings.py.
#
#   3: Test this script in command line directly, make sure no errors in output
#      message.
#
#       # python cleanup_amavisd_db.py
#
#   4: Setup a daily cron job to execute this script. For example: execute
#      it daily at 1:30AM.
#
#       30  1   *   *   *   python /path/to/cleanup_amavisd_db.py >/dev/null
#
# That's all.

import os
import sys
import time
import web

os.environ['LC_ALL'] = 'C'

rootdir = os.path.abspath(os.path.dirname(__file__)) + '/../'
sys.path.insert(0, rootdir)

import settings
from libs import iredutils
from tools import ira_tool_lib

web.config.debug = ira_tool_lib.debug
logger = ira_tool_lib.logger

if not (settings.amavisd_enable_logging or settings.amavisd_enable_quarantine):
    sys.exit("Amavisd is not enabled. SKIP.")

backend = settings.backend
logger.info('Backend: %s' % backend)
logger.info('SQL server: %s:%d' % (settings.amavisd_db_host, int(settings.amavisd_db_port)))

db_settings = iredutils.get_settings_from_db(params=['amavisd_remove_quarantined_in_days', 'amavisd_remove_maillog_in_days'])
keep_quar_days = db_settings['amavisd_remove_quarantined_in_days']
keep_inout_days = db_settings['amavisd_remove_maillog_in_days']
query_size_limit = settings.AMAVISD_CLEANUP_QUERY_SIZE_LIMIT

# SQL records in `quarantine` table reference to `msgs`.
if keep_quar_days > keep_inout_days:
    keep_inout_days = keep_quar_days

conn_amavisd = ira_tool_lib.get_db_conn('amavisd')

if settings.backend in ['mysql', 'ldap']:
    # Querying (SELECT) without locking. Require MySQL 5.0+ and InnoDB.
    #
    # Since we're dealing with sql records created days ago, no new records
    # will be inserted with that date, it's safe to use dirty read.
    logger.info('Enable dirty read for querying without locking SQL tables.')
    try:
        conn_amavisd.query('SET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED')
    except Exception as e:
        logger.error('Cannot enable dirty read: %s' % repr(e))


# Removing records from single table.
def remove_from_one_table(sql_table, index_column, removed_values):
    total = len(removed_values)

    # Delete how many records each time
    offset = query_size_limit

    if total:
        loop_times = total / offset
        if total % offset:
            loop_times += 1

        for i in range(int(loop_times)):
            removing_values = removed_values[offset * i: offset * (i + 1)]
            logger.info(
                '\t[-] Deleting records: %d - %d (%s)' % (i * offset, i * offset + len(removing_values), time.ctime()))
            conn_amavisd.delete(sql_table,
                                vars={'ids': removing_values},
                                where='%s IN $ids' % index_column)


# Delete old quarantined mails from table 'msgs'. It will also
# delete records in table 'quarantine'.
logger.info('Delete quarantined mails which older than %d days' % keep_quar_days)
_now = int(time.time())
_expire_seconds = _now - (keep_quar_days * 86400)
sql_where = """time_num < %d AND quar_type='Q'""" % _expire_seconds

counter_msgs = 0
while True:
    qr = conn_amavisd.select('msgs',
                             what='mail_id',
                             where=sql_where,
                             limit=query_size_limit)

    if qr:
        ids = [r.mail_id for r in qr]
        _total = len(ids)

        logger.info('\t[-] Deleting records: %d - %d (%s)' % (counter_msgs + 1, counter_msgs + _total, time.ctime()))

        conn_amavisd.delete('msgs', vars={'ids': ids}, where='mail_id IN $ids')
        conn_amavisd.delete('msgrcpt', vars={'ids': ids}, where='mail_id IN $ids')

        counter_msgs += len(ids)
    else:
        break

logger.info('Delete incoming/outgoing emails which older than %d days' % keep_inout_days)

_now = int(time.time())
_expire_seconds = _now - (keep_inout_days * 86400)
sql_where = """time_num < %d AND (quar_type <> 'Q' OR quar_type IS NULL)""" % _expire_seconds

# We experienced an issue with PostgreSQL, it always return an non-existing
# SQL record, and it causes endless loop. As a hack, we store all removed
# `mail_id` and compare new `mail_id` with this list.
_removed_ids = set()

counter_msgrcpt = 0
while True:
    qr = conn_amavisd.select('msgs',
                             what='mail_id',
                             where=sql_where,
                             limit=query_size_limit)

    if qr:
        ids = [iredutils.bytes2str(r.mail_id) for r in qr]
        _total = len(ids)

        _removing_ids = list(set(ids) - set(_removed_ids))
        if not _removing_ids:
            break

        logger.info(
            '\t[-] Deleting records: %d - %d (%s)' % (counter_msgrcpt + 1, counter_msgrcpt + _total, time.ctime()))

        conn_amavisd.delete('msgs', vars={'ids': _removing_ids}, where='mail_id IN $ids')
        conn_amavisd.delete('msgrcpt', vars={'ids': _removing_ids}, where='mail_id IN $ids')

        counter_msgrcpt += _total
        _removed_ids.update(ids)
    else:
        break

# delete unreferenced records from tables msgrcpt, quarantine and maddr
logger.info('Delete unreferenced records from table `msgrcpt`.')
conn_amavisd.query('''
    DELETE FROM msgrcpt
    WHERE NOT EXISTS (SELECT 1 FROM msgs WHERE mail_id=msgrcpt.mail_id)
''')

#
# Delete unreferenced records from table `quarantine`.
#
logger.info('Delete unreferenced records from table `quarantine`.')
msgs_mail_ids = set()
maddr_ids_in_use = set()
quar_mail_ids = set()

qr = conn_amavisd.select('msgs', what='mail_id, sid')
for i in qr:
    msgs_mail_ids.add(i.mail_id)
    maddr_ids_in_use.add(i.sid)

qr = conn_amavisd.select('quarantine', what='mail_id')
for i in qr:
    quar_mail_ids.add(i.mail_id)

invalid_quar_mail_ids = [i for i in quar_mail_ids if i not in msgs_mail_ids]
remove_from_one_table(sql_table='quarantine',
                      index_column='mail_id',
                      removed_values=invalid_quar_mail_ids)

#
# Delete unreferenced records from table `maddr`.
#
logger.info('Delete unreferenced records from table `maddr`.')

# Get all maddr.id
maddr_ids = set()
qr = conn_amavisd.select('maddr', what='id')
for i in qr:
    maddr_ids.add(i.id)

qr = conn_amavisd.select('msgrcpt', what='rid')
for i in qr:
    maddr_ids_in_use.add(i.rid)

invalid_maddr_ids = [i for i in maddr_ids if i not in maddr_ids_in_use]
remove_from_one_table(sql_table='maddr',
                      index_column='id',
                      removed_values=invalid_maddr_ids)

#
# Delete unreferenced records from table `mailaddr`.
#
logger.info('Delete unreferenced records from table `mailaddr`.')

# Get all `mailaddr.id`
mailaddr_ids = set()
qr = conn_amavisd.select('mailaddr', what='id')
for i in qr:
    mailaddr_ids.add(i.id)

# Get all `wblist.sid` and `outbound_wblist.rid` (both refer to `mailaddr.id`)
wblist_ids = set()

qr = conn_amavisd.select('wblist', what='sid')
for i in qr:
    wblist_ids.add(i.sid)

try:
    qr = conn_amavisd.select('outbound_wblist', what='rid')
    for i in qr:
        wblist_ids.add(i.rid)
except:
    # No outbound_wblist table
    pass

invalid_mailaddr_ids = [i for i in mailaddr_ids if i not in wblist_ids]
remove_from_one_table(sql_table='mailaddr',
                      index_column='id',
                      removed_values=invalid_mailaddr_ids)

logger.info('')
logger.info('Remained records:')
logger.info('')
logger.info('      `msgs`: %-7.d' % len(msgs_mail_ids))
logger.info('`quarantine`: %-7.d' % (len(quar_mail_ids) - len(invalid_quar_mail_ids)))
logger.info('     `maddr`: %-7.d' % (len(maddr_ids) - len(invalid_maddr_ids)))
logger.info('  `mailaddr`: %-7.d' % (len(mailaddr_ids) - len(invalid_mailaddr_ids)))

if counter_msgs \
        or counter_msgrcpt \
        or invalid_quar_mail_ids \
        or invalid_maddr_ids \
        or invalid_mailaddr_ids:
    msg = 'Removed records: '
    msg += '%d in msgs, ' % counter_msgs
    msg += '%d in msgrcpt, ' % counter_msgrcpt
    msg += '%d in quarantine, ' % len(invalid_quar_mail_ids)
    msg += '%d in maddr, ' % len(invalid_maddr_ids)
    msg += '%d in mailaddr.' % len(invalid_mailaddr_ids)

    ira_tool_lib.log_to_iredadmin(msg, admin='cleanup_amavisd_db', event='cleanup_db')
    logger.info('Log cleanup status.')
