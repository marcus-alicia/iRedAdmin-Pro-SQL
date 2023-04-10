#!/usr/bin/env python3
# Author: Zhang Huangbin <zhb@iredmail.org>
# Purpose: Library used by other scripts under tools/ directory.

import os
import sys
import logging
import web

debug = False

# Set True to print SQL queries.
web.config.debug = debug

os.environ['LC_ALL'] = 'C'

rootdir = os.path.abspath(os.path.dirname(__file__)) + '/../'
sys.path.insert(0, rootdir)

import settings
from libs import iredutils

backend = settings.backend
if backend in ['ldap', 'mysql']:
    sql_dbn = 'mysql'
elif backend in ['pgsql']:
    sql_dbn = 'postgres'
else:
    sys.exit('Error: Unsupported backend (%s).' % backend)

# logging
logger = logging.getLogger('iredadmin')
_ch = logging.StreamHandler(sys.stdout)
_formatter = logging.Formatter('* %(message)s')
_ch.setFormatter(_formatter)
logger.addHandler(_ch)
logger.setLevel(logging.INFO)


def get_db_conn(db_name):
    if backend == 'ldap' and db_name in ['ldap', 'vmail']:
        logger.error("""Please use code below to get LDAP connection cursor:\n

from libs.ldaplib.core import LDAPWrap\n
_wrap = LDAPWrap()\n
conn = _wrap.conn\n""")

        return None

    try:
        conn = web.database(
            dbn=sql_dbn,
            host=settings.__dict__[db_name + '_db_host'],
            port=int(settings.__dict__[db_name + '_db_port']),
            db=settings.__dict__[db_name + '_db_name'],
            user=settings.__dict__[db_name + '_db_user'],
            pw=settings.__dict__[db_name + '_db_password'],
        )

        conn.supports_multiple_insert = True
        return conn
    except Exception as e:
        logger.error(e)
        return None


# Log in `iredadmin.log`
def log_to_iredadmin(msg, event, admin='', username='', loglevel='info'):
    conn = get_db_conn('iredadmin')

    try:
        conn.insert('log',
                    admin=admin,
                    username=username,
                    event=event,
                    loglevel=loglevel,
                    msg=str(msg),
                    ip='127.0.0.1',
                    timestamp=iredutils.get_gmttime())
    except:
        pass

    return None


def sql_count_id(conn, table, column='id', where=None):
    if where:
        qr = conn.select(table,
                         what='count(%s) as total' % column,
                         where=where)
    else:
        qr = conn.select(table,
                         what='count(%s) as total' % column)
    if qr:
        total = qr[0].total
    else:
        total = 0

    return total
