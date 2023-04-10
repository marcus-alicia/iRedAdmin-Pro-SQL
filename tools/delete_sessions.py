#!/usr/bin/env python3

# Author: Zhang Huangbin <zhb@iredmail.org>
# Purpose: Delete all records in SQL table "iredadmin.sessions" to force
#          all admins to re-login.

import os
import sys
import web

os.environ['LC_ALL'] = 'C'

rootdir = os.path.abspath(os.path.dirname(__file__)) + '/../'
sys.path.insert(0, rootdir)

from tools import ira_tool_lib

web.config.debug = ira_tool_lib.debug
logger = ira_tool_lib.logger

conn = ira_tool_lib.get_db_conn('iredadmin')

logger.info('Delete all existing sessions to force all admins to re-login.')
conn.query('DELETE FROM sessions')
