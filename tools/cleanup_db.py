#!/usr/bin/env python3

# Author: Zhang Huangbin <zhb@iredmail.org>
# Purpose: Remove old records in iRedAdmin SQL database.

# USAGE:
#
#   1: Make sure you have proper values for below two parameters:
#
#       IREDADMIN_LOG_KEPT_DAYS = 30
#
#      Default values is defined in libs/default_settings.py, you can override
#      them in settings.py. WARNING: DO NOT MODIFY libs/default_settings.py.
#
#   2: Test this script in command line directly, make sure no errors in output
#      message.
#
#       # python cleanup_db.py
#
#   3: Setup a daily cron job to execute this script. For example: execute
#      it daily at 1:30AM.
#
#       30  1   *   *   *   python /path/to/cleanup_db.py >/dev/null
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
from tools.ira_tool_lib import debug, logger, sql_dbn, get_db_conn, sql_count_id

web.config.debug = debug

backend = settings.backend
logger.info('Backend: %s' % backend)
logger.info('SQL server: %s:%d' % (settings.iredadmin_db_host, int(settings.iredadmin_db_port)))

query_size_limit = 100

conn_iredadmin = get_db_conn('iredadmin')

#
# iredadmin.log
#
_days = settings.IREDADMIN_LOG_KEPT_DAYS
logger.info('Delete old admin activity log (> %d days)' % _days)

if sql_dbn == 'mysql':
    sql_where = """timestamp < DATE_SUB(NOW(), INTERVAL %d DAY)""" % _days
elif sql_dbn == 'postgres':
    sql_where = """timestamp < CURRENT_TIMESTAMP - INTERVAL '%d DAYS'""" % _days
else:
    logger.error('Invalid SQL backend: %s' % sql_dbn)
    sys.exit()

total_before = sql_count_id(conn_iredadmin, 'log')
conn_iredadmin.delete('log', where=sql_where)
total_after = sql_count_id(conn_iredadmin, 'log')
logger.info('\t- %d removed, %d left.' % (total_before - total_after, total_after))

#
# iredadmin.domain_ownership
#
_days = settings.DOMAIN_OWNERSHIP_EXPIRE_DAYS
logger.info('Delete old domain ownership verification records (> %d days)' % _days)

total_before = sql_count_id(conn_iredadmin, 'domain_ownership')
conn_iredadmin.delete('domain_ownership', where="expire > %d" % (_days * 24 * 60 * 60))
total_after = sql_count_id(conn_iredadmin, 'domain_ownership')
logger.info('\t- %d removed, %d left.' % (total_before - total_after, total_after))

#
# iredadmin.newsletter_subunsub_confirms
#
now = int(time.time())
_hours = settings.NEWSLETTER_SUBSCRIPTION_REQUEST_KEEP_HOURS
logger.info('Delete expired newsletter subscription confirm tokens (> %d hours)' % _hours)

total_before = sql_count_id(conn_iredadmin, 'newsletter_subunsub_confirms')
_expired = now - (_hours * 60 * 60)
conn_iredadmin.delete('newsletter_subunsub_confirms', where="expired <= %d" % _expired)
total_after = sql_count_id(conn_iredadmin, 'newsletter_subunsub_confirms')
logger.info('\t- %d removed, %d left.' % (total_before - total_after, total_after))
