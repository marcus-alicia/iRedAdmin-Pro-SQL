#!/usr/bin/env python3
# Author: Zhang Huangbin <zhb@iredmail.org>
# Purpose: Promote given user to be a global admin.
#          FYI https://docs.iredmail.org/promote.user.to.be.global.admin.html
# Usage:
#   python3 promote_to_global_admin.py <user-email>


def usage():
    print("""Usage: Run this script with user email address:

        # python3 promote_to_global_admin.py user@domain.com
    """)


import os
import sys

os.environ['LC_ALL'] = 'C'

rootdir = os.path.abspath(os.path.dirname(__file__)) + '/../'
sys.path.insert(0, rootdir)

import web
import settings
from tools.ira_tool_lib import debug, get_db_conn
from libs.iredutils import is_email

backend = settings.backend
web.config.debug = debug

# Check arguments
if len(sys.argv) == 2:
    email = sys.argv[1]

    if not is_email(email):
        usage()
        sys.exit()
else:
    usage()
    sys.exit()

if backend == 'ldap':
    from libs.ldaplib.core import LDAPWrap
    from libs.ldaplib import ldaputils
    _wrap = LDAPWrap()
    conn = _wrap.conn

    dn = ldaputils.rdn_value_to_user_dn(email)
    mod_attrs = ldaputils.attr_ldif(attr="enabledService", value="domainadmin", mode="add")
    mod_attrs += ldaputils.attr_ldif(attr="domainGlobalAdmin", value="yes", mode="add")

    try:
        conn.modify_s(dn, mod_attrs)
        print("User {} is now a global admin.".format(email))
    except Exception as e:
        print("<<< ERROR >>> {}".format(repr(e)))

elif backend in ['mysql', 'pgsql']:
    conn = get_db_conn('vmail')
    try:
        conn.update("mailbox",
                    isadmin=1,
                    isglobaladmin=1,
                    where="username='{}'".format(email))

        conn.insert("domain_admins",
                    username=email,
                    domain="ALL")

        print("User {} is now a global admin.".format(email))
    except Exception as e:
        print("<<< ERROR >>> {}".format(repr(e)))
