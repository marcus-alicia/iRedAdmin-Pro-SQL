#!/usr/bin/env python3
"""
Query user last login info from (My)SQL database and display it in a more
readable format (plain text or html).

Note: You need to follow this tutorial to enable last_login plugin in Dovecot:
      https://docs.iredmail.org/track.user.last.login.html

Usage:

    python3 export_last_login.py                        # in plain text format
    python3 export_last_login.py html > export.html     # in html format
"""
import os
import sys
import time
import web

os.environ['LC_ALL'] = 'C'

rootdir = os.path.abspath(os.path.dirname(__file__)) + '/../'
sys.path.insert(0, rootdir)

import settings
from tools import ira_tool_lib
from libs.iredutils import epoch_seconds_to_gmt

web.config.debug = ira_tool_lib.debug
logger = ira_tool_lib.logger

if settings.backend == 'ldap':
    conn = ira_tool_lib.get_db_conn('iredadmin')
else:
    conn = ira_tool_lib.get_db_conn('vmail')

# Get output format
try:
    export_format = sys.argv[1]
except:
    export_format = 'text'

try:
    qr = conn.select('last_login',
                     order='last_login DESC')
except Exception as e:
    sys.exit("Query failed: {}".format(e))

if export_format == 'html':
    _now = time.strftime('%Y-%d-%m %H:%M:%S')

    html = """<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html>
<head>
    <meta http-equiv="Content-type" content="text/html; charset=utf-8" />
    <style type="text/css">
        .th_size, .th_date, .td_size, .td_date {{ white-space: nowrap; }}
        .tr_date {{ background-color: #DDDDDD; }}
        .text_align_left {{ text-align: left; }}
    </style>
</head>

<body>
    <h3>User Last Login Time ({0})</h3>
    <table>
        <thead>
            <tr>
                <th>#</th>
                <th>Email</th>
                <th>Time (GMT)</th>
            </tr>
        </thead>
        <tbody>
    """.format(_now)

counter = 1
for row in qr:
    username = row.username
    seconds = row.last_login
    last_login = epoch_seconds_to_gmt(seconds)

    if export_format == 'html':
        html += """
            <tr>
                <td>{}</td>
                <td>{}</td>
                <td>{}</td>
            </tr>
        """.format(counter, username, last_login)
    else:
        print("{:6} | {:30} | {}".format(counter, username, last_login))

    counter += 1

if export_format == 'html':
    html += """</tbody></table></body></html>"""
    print(html)
