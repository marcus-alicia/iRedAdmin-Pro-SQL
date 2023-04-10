#!/usr/bin/env python3

# Author: Zhang Huangbin <zhb@iredmail.org>
# Purpose: Migrate Cluebringer white/blacklist to Amavisd database.
#
# Note: it's safe to execute this script as many times as you want, it won't
#       generate duplicate records.

import os
import sys
import web

os.environ['LC_ALL'] = 'C'

rootdir = os.path.abspath(os.path.dirname(__file__)) + '/../'
sys.path.insert(0, rootdir)

import settings
from libs.iredutils import is_valid_amavisd_address
from libs.amavisd import wblist
from tools import ira_tool_lib

web.config.debug = ira_tool_lib.debug
logger = ira_tool_lib.logger

# Check database name to make sure it's Cluebringer
if settings.policyd_db_name != 'cluebringer':
    sys.exit('Error: not a Cluebringer database.')

logger.info('Establish SQL connection.')
conn = ira_tool_lib.get_db_conn('policyd')

logger.info('Query white/blacklist info.')

# Converted wblist
wl = []
bl = []

# value of sql column: policy_groups.id
wl_id = None
bl_id = None
wb_ids = []

# query whitelist and/or blacklist. possible values: 'wl', 'bl'.
query_lists = []

# get policy_groups.id
qr = conn.select('policy_groups', what='id,name', where="name IN ('whitelists', 'blacklists')")
if qr:
    for r in qr:
        if r.name == 'whitelists':
            wl_id = r.id
        elif r.name == 'blacklists':
            bl_id = r.id

    if wl_id:
        logger.info('policy_groups.id: %d -> whitelists' % wl_id)
        query_lists.append('wl')
        wb_ids.append(wl_id)

    if bl_id:
        logger.info('policy_groups.id: %d -> blacklists' % bl_id)
        query_lists.append('bl')
        wb_ids.append(bl_id)
else:
    logger.info('No whitelist/blacklist found. Exit.')
    sys.exit()

logger.info('Query all whitelists and blacklists.')
qr = conn.select('policy_group_members',
                 vars={'wb_ids': wb_ids},
                 what='policygroupid, member',
                 where='policygroupid IN $wb_ids AND disabled=0')

if qr:
    logger.info('Convert Cluebringer white/blacklists to Amavisd syntax format.')
    for r in qr:
        # Single IP Address: 192.168.2.10
        # CIDR formatted range of IP addresses: 192.168.2.10/31
        # Single user: user@example.com
        # Entire domain: @example.com
        # All sub-domains: .example.com
        value = None
        if is_valid_amavisd_address(r.member):
            value = r.member
        else:
            # Convert from different syntax format
            if r.member.startswith('.'):
                tmp = '@' + r.member
                if is_valid_amavisd_address(tmp):
                    value = tmp
                else:
                    logger.info('[?] Discard record in improper format: %s, cannot convert.' % r.member)
            elif '/' in r.member:
                logger.info('[?] Discard record in improper format: %s. CIDR IP range is not supported.' % r.member)

        if value:
            if r.policygroupid == wl_id:
                wl.append(value)
            else:
                bl.append(value)

if wl:
    logger.info('Converted whitelisted: %d total' % len(wl))
else:
    logger.info('No whitelists found.')

if bl:
    logger.info('Converted blacklisted: %d total' % len(bl))
else:
    logger.info('No blacklists found.')

confirm = input('Migrate converted white/blacklists to Amavisd database right now? [y|N]')
if confirm not in ['y', 'Y', 'yes', 'YES']:
    logger.info('Exit without migrating to Amavisd database.')
    sys.exit()

# Import to Amavisd database.
try:
    logger.info('Migrating, please wait ...')
    wblist.add_wblist(account='@.',
                      wl_senders=wl,
                      bl_senders=bl,
                      flush_before_import=False)

    logger.info("Don't forget to enable iRedAPD plugin 'amavisd_wblist' in /opt/iredapd/settings.py.")
except Exception as e:
    logger.info(str(e))

# Ask to delete wblist in cluebringer
confirm = input('Delete all white/blacklists stored in Cluebringer database? [y|N]')
if confirm not in ['y', 'Y', 'yes', 'YES']:
    logger.info('Exit without deleting Cluebringer white/blacklists.')
    sys.exit()

conn.delete('policy_group_members', vars={'wb_ids': wb_ids}, where='policygroupid IN $wb_ids')
conn.delete('policy_groups', vars={'wb_ids': wb_ids}, where='id IN $wb_ids')
conn.delete('policy_members', where="destination='%%internal_domains' AND source IN ('%%whitelists', '%%blacklists')")

# Get policies.id
qr = conn.select('policies', what='id', where="name IN ('whitelists', 'blacklists')")
if qr:
    pids = [r.id for r in qr]

    conn.delete('access_control', vars={'pids': pids}, where='policyid IN $pids')
    conn.delete('policies', vars={'pids': pids}, where='id IN $pids')

logger.info('DONE')
