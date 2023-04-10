#!/usr/bin/env python3

# Author: Zhang Huangbin <zhb@iredmail.org>
# Purpose: Update user passwords from records in a CSV file.

import os
import sys
import web


def usage():
    print("""Usage:

    - Store the email address and new password in a plain text file, e.g.
      'passwords.csv'. format is:

          <email> <new_password>

      Samples:

        user1@domain.com pF4mTq4jaRzDLlWl
        user2@domain.com SPhkTUlZs1TBxvmJ
        user3@domain.com 8deNR8IBLycRujDN

   - Run this script with this file:

        python3 update_password_in_csv.py passwords.csv
    """)


os.environ['LC_ALL'] = 'C'

rootdir = os.path.abspath(os.path.dirname(__file__)) + '/../'
sys.path.insert(0, rootdir)

import settings
from tools.ira_tool_lib import debug, logger, get_db_conn
from libs.iredutils import is_email
from libs.iredpwd import generate_password_hash

backend = settings.backend
logger.info('Backend: %s' % backend)

web.config.debug = debug

logger.info('Parsing command line arguments.')

# File which stores email and quota.
text_file = ''

# The separator
column_separator = ' '

# List of (email, quota) tuples.
users = []

# Check arguments
if len(sys.argv) == 2:
    text_file = sys.argv[1]
    if not os.path.isfile(text_file):
        sys.exit('<<< ERROR>>> Not a regular file: %s' % text_file)

    # Get all (email, password) tuples.
    f = open(text_file)
    line_num = 0
    for _line in f.readlines():
        line_num += 1
        (_email, _pw) = _line.split(column_separator, 1)
        if is_email(_email):
            users += [(_email, _pw)]
        else:
            print("[SKIP] line {}: no valid email address: {}".format(line_num, _line))
    f.close()
else:
    usage()

total = len(users)
logger.info('%d users in total.' % total)

count = 1
if backend == 'ldap':
    from libs.ldaplib.core import LDAPWrap
    from libs.ldaplib.ldaputils import rdn_value_to_user_dn, mod_replace
    _wrap = LDAPWrap()
    conn = _wrap.conn

    for (_email, _pw) in users:
        logger.info('(%d/%d) Updating %s' % (count, total, _email))

        dn = rdn_value_to_user_dn(_email)
        pw_hash = generate_password_hash(_pw)
        mod_attrs = mod_replace('userPassword', pw_hash)
        try:
            conn.modify_s(dn, mod_attrs)
        except Exception as e:
            print("<<< ERROR >>> {}".format(repr(e)))
elif backend in ['mysql', 'pgsql']:
    conn = get_db_conn('vmail')
    for (_email, _pw) in users:
        logger.info('(%d/%d) Updating %s' % (count, total, _email))
        pw_hash = generate_password_hash(_pw)
        conn.update('mailbox',
                    password=pw_hash,
                    where="username='%s'" % _email)
