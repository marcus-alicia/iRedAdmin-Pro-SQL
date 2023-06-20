#!/usr/bin/env python3

# Author: Zhang Huangbin <zhb@iredmail.org>
# Purpose: Delete mailboxes which are scheduled to be removed.
#
# Notes: iRedAdmin will store maildir path of removed mail users in SQL table
#        `iredadmin.deleted_mailboxes` (LDAP backends) or
#        `vmail.deleted_mailboxes` (SQL backends).
#
# Usage: Either run this script manually, or run it with a daily cron job.
#
#   # python3 delete_mailboxes.py
#
# Available arguments:
#
#   * --delete-without-timestamp:
#
#       [RISKY] If no timestamp string in maildir path, continue to delete it.
#
#       With default iRedMail settings, maildir path will contain a timestamp
#       like this: <domain.com>/u/s/e/username-2016.08.17.09.53.03/
#       (2016.08.17.09.53.03 is the timestamp), this way all created maildir
#       paths are unique, even if you removed the user and recreate it with
#       same mail address.
#
#       Without timestamp in maildir path (e.g. <domain.com>/u/s/e/username/),
#       if you removed a user and recreate it someday, this user will see old
#       emails in old mailbox (because maildir path is same as old user's). So
#       it becomes RISKY to remove the mailbox if no timestamp in maildir path.
#
#   * --delete-null-date:
#
#       Delete mailbox if SQL column `deleted_mailboxes.delete_date` is null.
#
#   * --debug: print additional log

import os
import sys
import time
import logging
import shutil
import pwd

os.environ['LC_ALL'] = 'C'

rootdir = os.path.abspath(os.path.dirname(__file__)) + '/../'
sys.path.insert(0, rootdir)

import web
from libs import iredutils
from tools import ira_tool_lib
import settings

web.config.debug = ira_tool_lib.debug
logger = ira_tool_lib.logger

if '--debug' in sys.argv:
    logger.setLevel(logging.DEBUG)

# Delete if `deleted_mailboxes.delete_date` is null.
delete_null_date = False
if '--delete-null-date' in sys.argv:
    delete_null_date = True

# Make sure there's a timestamp (yyyy.mm.dd.hh.mm.ss) in maildir path,
# otherwise it's too risky to remove this mailbox -- because the maildir
# could be reused by another user after old account was removed.
#
#   - Safe to remove: <domain.com>/u/s/e/username-<timestamp>/
#   - Dangerous to remove: <domain.com>/u/s/e/username/
delete_without_timestamp = False
if '--delete-without-timestamp' in sys.argv:
    delete_without_timestamp = True


def delete_record(conn_deleted_mailboxes, rid):
    try:
        conn_deleted_mailboxes.delete('deleted_mailboxes',
                                      vars={'id': rid},
                                      where='id=$id')

        return True,
    except Exception as e:
        return False, repr(e)


def delete_mailbox(conn_deleted_mailboxes,
                   record,
                   all_maildirs=None):
    rid = record.id
    username = str(record.username).lower()
    timestamp = str(record.timestamp)
    delete_date = record.delete_date

    maildir = record.maildir
    maildir = maildir.replace('//', '/')    # Remove duplicate '/'

    if delete_without_timestamp:
        # Make sure no other mailbox is stored under the maildir.
        if all_maildirs:
            if not maildir.endswith('/'):
                maildir += '/'

            for mdir in all_maildirs:
                if mdir.startswith(maildir) or (mdir == maildir):
                    logger.error("<<< ABORT, CRITICAL >>> Trying to remove mailbox ({}) owned by user ({}), but there is another mailbox ({}) stored under this directory. Aborted.".format(maildir, username, mdir))
                    return False
    else:
        _dir = maildir.rstrip('/')

        if len(_dir) <= 21:
            # Why 21 chars:
            #   - 20 chars: "-<timestamp>". e.g. "-2014.03.26.15.07.25"
            #   - username contains at least 1 char
            logger.error("<<< SKIP >>> Seems no timestamp in maildir path (%s), too risky to remove this mailbox." % maildir)
            return False

        try:
            # Extract timestamp string, make sure it's a valid time format.
            ts = _dir[-19:]
            time.strptime(ts, '%Y.%m.%d.%H.%M.%S')
        except Exception as e:
            logger.debug("<<< WARNING >>> Invalid or missing timestamp in maildir path (%s), skip." % maildir)
            logger.debug("<<< WARNING >>> Error message: %s." % repr(e))
            return False

    # check maildir path
    if os.path.isdir(maildir):
        # Make sure directory is owned by vmail:vmail
        _dir_stat = os.stat(maildir)
        _dir_uid = _dir_stat.st_uid

        # Get uid/gid of vmail user
        owner = pwd.getpwuid(_dir_uid).pw_name
        if owner != 'vmail':
            logger.error('<<< ERROR >> Directory is not owned by `vmail` user: uid -> {}, user -> {}.'.format(_dir_uid, owner))
            return False

        try:
            msg = '[{}] {}.'.format(username, maildir)
            msg += ' Account was deleted at {}.'.format(timestamp)
            if delete_date:
                msg += ' Mailbox was scheduled to be removed on {}.'.format(delete_date)
            else:
                msg += ' Mailbox was scheduled to be removed as soon as possible.'

            logger.info(msg)

            logger.info("Removing mailbox: {}".format(maildir))
            # Delete mailbox
            shutil.rmtree(maildir)

            # Log this deletion.
            ira_tool_lib.log_to_iredadmin(msg,
                                          admin='cron_delete_mailboxes',
                                          username=username,
                                          event='delete_mailboxes')
        except Exception as e:
            logger.error('<<< ERROR >> while deleting mailbox ({} -> {}): {}'.format(username, maildir, repr(e)))

    # Delete record.
    delete_record(conn_deleted_mailboxes=conn_deleted_mailboxes, rid=rid)


# Establish SQL connection.
try:
    if settings.backend == 'ldap':
        conn_deleted_mailboxes = ira_tool_lib.get_db_conn('iredadmin')

        from libs.ldaplib.core import LDAPWrap
        _wrap = LDAPWrap()
        conn_vmail = _wrap.conn
    else:
        conn_deleted_mailboxes = ira_tool_lib.get_db_conn('vmail')
        conn_vmail = conn_deleted_mailboxes
except Exception as e:
    sys.exit('<<< ERROR >>> Cannot connect to SQL database, aborted. Error: %s' % repr(e))

# Get paths of all maildirs.
sql_where = 'delete_date <= %s' % web.sqlquote(web.sqlliteral('NOW()'))
if delete_null_date:
    sql_where = '(delete_date <= %s) OR (delete_date IS NULL)' % web.sqlquote(web.sqlliteral('NOW()'))

qr_mailboxes = conn_deleted_mailboxes.select('deleted_mailboxes', where=sql_where)
if not qr_mailboxes:
    logger.debug('No mailbox is scheduled to be removed.')

    if not delete_null_date:
        logger.debug("To remove mailboxes without schedule date, please run this script with argument '--delete-null-date'.")

    if not delete_without_timestamp:
        logger.debug("To remove mailboxes without timesamp in maildir path, please run this script with argument '--delete-without-timestamp'. [WARNING] It's RISKY.")

    sys.exit()

# Get all maildir paths used by active mail users.
#
# To delete mailbox without timestamp in maildir path, we must make sure:
#   - maildir is not used by some active user
#   - no other mailbox is stored under this maildir path
#
# Q: Why query all maildir paths instead of querying SQL/LDAP directly?
# A:
#   1. LDAP attribute `homeDirectory` doesn't support `sub` (substring) index.
#   2. if maildir path contains duplicate '/', the validation will fail (not
#      equal).
all_maildirs = []
if delete_without_timestamp:
    if settings.backend == 'ldap':
        _qr = conn_vmail.search_s(settings.ldap_basedn,
                                  2,     # ldap.SCOPE_SUBTREE
                                  "(objectClass=mailUser)",
                                  ['homeDirectory'])
        for (_dn, _ldif) in _qr:
            _ldif = iredutils.bytes2str(_ldif)
            if 'homeDirectory' in _ldif:
                _dir = _ldif['homeDirectory'][0].lower().replace('//', '/')
                all_maildirs.append(_dir)
    elif settings.backend in ['mysql', 'pgsql']:
        # WARNING: always append '/' in returned maildir path.
        _qr = conn_vmail.select('mailbox',
                                what="LOWER(CONCAT(storagebasedirectory, '/', storagenode, '/', maildir, '/')) AS maildir")

        all_maildirs = [str(i.maildir).replace('//', '/') for i in _qr]

for r in list(qr_mailboxes):
    delete_mailbox(conn_deleted_mailboxes=conn_deleted_mailboxes,
                   record=r,
                   all_maildirs=all_maildirs)
