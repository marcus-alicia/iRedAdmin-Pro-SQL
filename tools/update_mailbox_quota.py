#!/usr/bin/env python

# Author: Zhang Huangbin <zhb@iredmail.org>
# Purpose: Update mailbox quota for one user or multiple users.
# Note: Mailbox quota size unit is bytes. for example, size `104857600` is 100 MB.


def usage():
    print("""Usage:

    1) Update mailbox quota for one user.

       To simply update one user's quota, run this script with user's email
       address and new quota size (in bytes). For example:

        # python3 update_mailbox_quota.py user@domain.com 2048576000

    2) Update mailbox quota for multiple users.

       - Create text file "new_quota.txt", each line contains one email address
         and the new quota size (in bytes).

            user1@domain.com 20480000
            user2@domain.com 102400000
            user3@domain.com 409600000

       - Run this script with this file:

            # python3 update_mailbox_quota.py new_quota.txt
    """)


import os
import sys
import web

os.environ['LC_ALL'] = 'C'

rootdir = os.path.abspath(os.path.dirname(__file__)) + '/../'
sys.path.insert(0, rootdir)

import settings
from tools.ira_tool_lib import debug, logger, get_db_conn
from libs.iredutils import is_email

backend = settings.backend
logger.info('Backend: {}'.format(backend))

web.config.debug = debug

# List of (email, quota) tuples.
users = []

# Check arguments
if len(sys.argv) == 2:
    # bulk update
    text_file = sys.argv[1]
    if not os.path.isfile(text_file):
        sys.exit('<<< ERROR>>> Not a regular file: %s' % text_file)

    # Get all (email, quota) tuples.
    f = open(text_file)
    for _line in f.readlines():
        (_email, _quota) = _line.strip().split(' ', 1)
        if is_email(_email) and _quota.isdigit():
            users += [(_email, _quota)]
        else:
            print("[SKIP] no valid email address or quota: {}".format(_line))

elif len(sys.argv) == 3:
    # update single user
    _email = sys.argv[1]
    _quota = sys.argv[2]

    if is_email(_email):
        users += [(_email, _quota)]
    else:
        sys.exit('<<< ERROR >>> Not an valid email address: %s' % _email)
else:
    usage()

total = len(users)
logger.info('{} users in total.'.format(total))

count = 1
if backend == 'ldap':
    from libs.ldaplib.core import LDAPWrap
    from libs.ldaplib.ldaputils import rdn_value_to_user_dn, mod_replace
    _wrap = LDAPWrap()
    conn = _wrap.conn

    for (_email, _quota) in users:
        logger.info('(%d/%d) Updating %s -> %s' % (count, total, _email, _quota))
        dn = rdn_value_to_user_dn(_email)
        mod_attrs = mod_replace('mailQuota', _quota)
        try:
            conn.modify_s(dn, mod_attrs)
        except Exception as e:
            print("<<< ERROR >>> {}".format(e))
elif backend in ['mysql', 'pgsql']:
    conn = get_db_conn('vmail')
    for (_email, _quota) in users:
        logger.info('(%d/%d) Updating %s -> %s' % (count, total, _email, _quota))
        conn.update('mailbox',
                    quota=int(_quota),
                    where="username='%s'" % _email)
