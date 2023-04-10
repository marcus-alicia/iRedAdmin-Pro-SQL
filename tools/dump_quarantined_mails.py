#!/usr/bin/env python3
# Author: Zhang Huangbin <zhb@iredmail.org>
# Purpose: Dump quarantined emails to given directory (specified on command line).
#
# Usage:
#
#   python dump_quarantined_mail.py /path/to/dir

import os
import sys
import time
import web

output_dir = sys.argv[1]
if not os.path.isdir(output_dir):
    sys.exit("Output directory doesn't exist: %s" % output_dir)

os.environ['LC_ALL'] = 'C'

rootdir = os.path.abspath(os.path.dirname(__file__)) + '/../'
sys.path.insert(0, rootdir)

from tools.ira_tool_lib import debug, get_db_conn

web.config.debug = debug

now = int(time.time())
conn_amavisd = get_db_conn('amavisd')
conn_iredadmin = get_db_conn('iredadmin')

# Get last time
last_time = 0
try:
    qr = conn_iredadmin.select('tracking', what='v', where="k='dump_quarantined_mail'", limit=1)
    if qr:
        last_time = int(qr[0].v)
except:
    pass

# Get value of all `quarantine.mail_id`.
try:
    qr = conn_amavisd.select(['msgs', 'quarantine'],
                             what='msgs.mail_id AS mail_id',
                             where='msgs.mail_id=quarantine.mail_id AND msgs.time_num >= %d' % last_time,
                             group='msgs.mail_id')
except Exception as e:
    print('<<< ERROR >>> {}'.format(repr(e)))
    sys.exit()

total = len(qr)
print("* Found {} quarantined emails in SQL db.".format(total))

counter = 1
for r in qr:
    mail_id = str(r.mail_id)
    try:
        records = conn_amavisd.select('quarantine',
                                      what='mail_text',
                                      where='mail_id = %s' % web.sqlquote(mail_id),
                                      order='chunk_ind ASC')

        if not records:
            continue

        # Combine mail_text as RAW mail message.
        message = ''
        for i in list(records):
            for j in i.mail_text:
                message += j

        # Write message to file
        try:
            eml_path = os.path.join(output_dir, 'spam-' + mail_id)
            print("[{}/{}] Dumping email to file: {}".format(counter, total, eml_path))

            f = open(eml_path, 'w')
            f.write(message)
            f.close()
        except Exception as e:
            print('<<< ERROR >>> cannot write file {}'.format(repr(e)))
    except Exception as e:
        print("<<< ERROR >>> {}".format(repr(e)))

    counter += 1

# Log last time.
conn_iredadmin.delete('tracking', where="k='dump_quarantined_mail'")
conn_iredadmin.insert('tracking', k='dump_quarantined_mail', v=now)
