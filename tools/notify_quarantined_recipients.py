#!/usr/bin/env python3

# Author: Zhang Huangbin <zhb@iredmail.org>
# Purpose: Notify local recipients (via email) that they have emails
#          quarantined on server and not delivered to their mailbox.

# Usage:
#
#   - Set a correct URL in iRedAdmin-Pro config file `settings.py`, so that
#     users can manage quarantined email within received notification email:
#
#       # URL of your iRedAdmin-Pro login page which will be shown in notification
#       # email, so that user can login to manage quarantined emails.
#       # Sample: 'https://your_server.com/iredadmin/'
#       #
#       # Note: mail domain must have self-service enabled, otherwise normal
#       #       mail user cannot login to iRedAdmin-Pro for self-service.
#       NOTIFICATION_URL_SELF_SERVICE = 'https://[your_server]/iredadmin/'
#
#   - Setup a cron job to run this script every 6 or 12, 24 hours, it's up to
#     you. Sample cron job (every 12 hours):
#
#       1 */12 * * * python /path/to/notify_quarantined_recipients.py >/dev/null
#
#     Available arguments:
#
#       --force-all:
#           Send notification to all users (who have email quarantined).
#
#       --force-all-time:
#           Notify users for their all quarantined emails instead of just new
#           ones since last notification.
#
#       --notify-backupmx
#           Send notification to all recipients under backup mx domain
#
#   - Also, it's ok to run this script manually:
#
#       # python notify_quarantined_recipients.py [arg1 arg2 arg3 ...]

# Customization
#
#   - This script sends email via /usr/sbin/sendmail command by default, it
#     should work quite well and has better performance. if you still prefer
#     to send notification email via smtp, please set proper smtp server and
#     account info in iRedAdmin-Pro config file `settings.py`:
#
#       NOTIFICATION_SMTP_SERVER = 'localhost'
#       NOTIFICATION_SMTP_PORT = 587
#       NOTIFICATION_SMTP_STARTTLS = True
#       NOTIFICATION_SMTP_USER = ''
#       NOTIFICATION_SMTP_PASSWORD = ''
#
#   - To custom mail subject of notification email, please define below
#     variable in iRedAdmin-Pro config file `settings.py`:
#
#       # Subject of notification email.
#       NOTIFICATION_QUARANTINE_MAIL_SUBJECT = '[Attention] You have emails quarantined and not delivered to mailbox'
#
#   - To custom HTML template file, please create your own template file with
#     correct name in either place:
#
#       - `/opt/iredmail/custom/iredadmin/notify_quarantined_recipients.html`
#
#           This file is used if your iRedMail server was deployed with the
#           iRedMail Easy platform (https://www.iredmail.org/easy.html), easy
#           for iRedAdmin-Pro upgrade.
#
#       - `tools/notify_quarantined_recipients.html.custom` under iRedAdmin-Pro
#          directory.
#
#           General use. Note: there's a `.custom` suffix in file name.
#
#     If no custom file, `tools/notify_quarantined_recipients.html` will be used.
#
# How it works:
#
#   - Mail user login to iRedAdmin-Pro (self-service) and choose to receive
#     notification email when there's email quarantined.
#
#       - OpenLDAP: user will be assigned `enabledService=quar_notify`.
#       - SQL backends: column `mailbox.settings` contains `quar_notify:yes`.
#
#   - This script queries SQL/LDAP database to see who are willing to receive
#     a notification email.
#
#   - This script checks Amavisd database to get info of quarantined mails
#     for these users.

import os
import sys
import time
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.header import Header

os.environ['LC_ALL'] = 'C'

script_dir = os.path.abspath(os.path.dirname(__file__))
rootdir = script_dir + '/../'
sys.path.insert(0, rootdir)

now = int(time.time())

import web
import settings
from libs import iredutils
from libs.ireddate import utc_to_timezone
from tools import ira_tool_lib

web.config.debug = ira_tool_lib.debug
logger = ira_tool_lib.logger

backend = settings.backend

# Read template HTML file.
custom_easy_tmpl = "/opt/iredmail/custom/iredadmin/notify_quarantined_recipients.html"
custom_tmpl = os.path.join(rootdir, 'tools', 'notify_quarantined_recipients.html.custom')
default_tmpl = os.path.join(rootdir, 'tools', 'notify_quarantined_recipients.html')

if os.path.isfile(custom_easy_tmpl):
    html_tmpl = custom_easy_tmpl
elif os.path.isfile(custom_tmpl):
    html_tmpl = custom_tmpl
else:
    html_tmpl = default_tmpl

# Info used in notification email.
mail_subject = settings.NOTIFICATION_QUARANTINE_MAIL_SUBJECT
smtp_user = settings.NOTIFICATION_SMTP_USER
iredadmin_url = settings.NOTIFICATION_URL_SELF_SERVICE

# Use '--force-all' option to notify all mail users.
force_all_users = '--force-all' in sys.argv or False
force_all_time = '--force-all-time' in sys.argv or False
notify_backupmx = '--notify-backupmx' in sys.argv or False

# Backup MX domains.
# We may not have any accounts under backup mx domain, so if sys admin chooses
# to notify recipients in backup mx domain, we send the notification also.
backupmx_domains = []

# List of target users' email address.
target_users = []

# Get list of users (email) who asked to receive notification email.
if settings.backend == 'ldap':
    from libs.ldaplib.core import LDAPWrap
    _wrap = LDAPWrap()
    conn_ldap = _wrap.conn

    # Get users who ask to get a notification email under each domain.
    if force_all_users:
        q_filter = '(&(objectClass=mailUser)(accountStatus=active))'
    else:
        q_filter = '(&(objectClass=mailUser)(accountStatus=active)(enabledService=quar_notify))'

    try:
        qr = conn_ldap.search_s(settings.ldap_basedn,
                                2,     # ldap.SCOPE_SUBTREE,
                                q_filter,
                                ['mail'])
        for (_dn, _ldif) in qr:
            _ldif = iredutils.bytes2str(_ldif)
            target_users += _ldif.get('mail', [])
    except Exception as e:
        logger.info('<< ERROR >> Error while querying mail users: %s' % repr(e))

    if notify_backupmx:
        # Query all backup mx domains
        q_filter = '(&(objectClass=mailDomain)(accountStatus=active)(domainBackupMX=yes)(mtaTransport=relay:*))'

        try:
            qr = conn_ldap.search_s(settings.ldap_basedn,
                                    1,     # ldap.SCOPE_ONELEVEL,
                                    q_filter,
                                    ['domainName', 'domainAliasName'])
            for (_dn, _ldif) in qr:
                _ldif = iredutils.bytes2str(_ldif)
                backupmx_domains += _ldif.get('domainName', [])
                backupmx_domains += _ldif.get('domainAliasName', [])
        except Exception as e:
            logger.info('<< ERROR >> Error while querying backup MX domains: %s' % repr(e))

elif settings.backend in ['mysql', 'pgsql']:
    conn_vmaildb = ira_tool_lib.get_db_conn('vmail')

    # Get all users who asked to receive notification email.
    if force_all_users:
        sql_where = 'active=1'
    else:
        sql_where = 'settings LIKE %s AND active=1' % web.sqlquote('%' + 'quar_notify:' + '%')

    qr = conn_vmaildb.select('mailbox',
                             what='username',
                             where=sql_where)

    for r in qr:
        target_users.append(r.username)

    if notify_backupmx:
        # Get all backup mx domains
        qr = conn_vmaildb.select('domain',
                                 what='domain',
                                 where='backupmx=1 AND active=1')
        for i in qr:
            backupmx_domains += [str(i.domain).lower()]

    if backupmx_domains:
        # Get all alias domains
        qr = conn_vmaildb.select('alias_domain',
                                 vars={'domains': backupmx_domains},
                                 what='alias_domain',
                                 where='target_domain IN $domains')

        for i in qr:
            backupmx_domains += [str(i.alias_domain).lower()]

if not (target_users or backupmx_domains):
    logger.debug('No user asks to receive notification email. Exit.')
    sys.exit()

mail_body_template = open(html_tmpl).read()

conn_amavisd = ira_tool_lib.get_db_conn('amavisd')
conn_iredadmin = ira_tool_lib.get_db_conn('iredadmin')

reversed_backupmx_domains = []
target_backupmx_users = []
if backupmx_domains:
    for d in backupmx_domains:
        rd = d.split('.')
        rd.reverse()
        rd = '.'.join(rd)

        reversed_backupmx_domains.append(rd)

    qr = conn_amavisd.select('maddr',
                             vars={'rcpt': reversed_backupmx_domains},
                             what='email',
                             where='domain IN $rcpt')
    for i in qr:
        _email = iredutils.bytes2str(i.email)
        target_backupmx_users.append(_email)

    logger.info('%d backup MX domains (%d users) will receive notification email.' % (len(backupmx_domains), len(target_backupmx_users)))

logger.debug('%d users are willing to receive notification email.' % len(target_users))

target_users += target_backupmx_users

# Notify users.
for user in target_users:
    # Get maddr.id of recipient
    qr = conn_amavisd.select('maddr',
                             vars={'rcpt': user},
                             what='id',
                             where='email=$rcpt',
                             limit=1)
    if qr:
        rid = qr[0].id
    else:
        logger.debug('[SKIP] No log of user: ' + user)
        continue

    # Get info of quarantined mails
    sql_what = 'msgrcpt.rid AS rid,' \
               + 'msgs.mail_id AS mail_id,' \
               + 'msgs.subject AS subject,' \
               + 'msgs.from_addr AS from_addr,' \
               + 'msgs.spam_level AS spam_level,' \
               + 'msgs.time_num'

    sql_where = """msgrcpt.rid=$rid AND msgs.mail_id=msgrcpt.mail_id AND msgs.quar_type='Q'"""

    last_notify_time = 0
    if not force_all_time:
        # Get last time
        try:
            qr = conn_iredadmin.select('tracking', what='v', where="k='quarantine_notify_time'", limit=1)
            if qr:
                last_notify_time = int(qr[0].v) or 0
        except:
            pass

    if last_notify_time:
        sql_where += """ AND msgs.time_num >= %s""" % last_notify_time

    qr = conn_amavisd.select(['msgs', 'msgrcpt'],
                             vars={'rid': rid},
                             what=sql_what,
                             where=sql_where,
                             order='msgs.time_num DESC')

    if not qr:
        logger.debug('[SKIP] No quarantined emails for %s.' % user)
        continue

    total = len(qr)

    # Group messages by date.
    info_by_date = {}

    quar_mail_info = '\n'

    # Create a HTML table to present quarantined emails.
    for rcd in qr:
        # time format: Apr 4, 2015
        dt = iredutils.epoch_seconds_to_gmt(iredutils.bytes2str(rcd.time_num))
        time_with_tz = utc_to_timezone(dt=dt, timezone=settings.LOCAL_TIMEZONE)
        try:
            time_tuple = time_with_tz.timetuple()
        except:
            time_tuple = time.strptime(time_with_tz, '%Y-%m-%d %H:%M:%S')

        mail_date = time.strftime('%b %d, %Y', time_tuple)
        mail_time = time.strftime('%H:%M:%S', time_tuple)

        info = '<tr>' + '\n'
        info += '<td class="td_subject">' + iredutils.bytes2str(rcd.subject) + '</td>' + '\n'
        info += '<td class="td_sender">' + iredutils.bytes2str(rcd.from_addr) + '</td>' + '\n'
        info += '<td class="td_spam_level">' + iredutils.bytes2str(rcd.spam_level) + '</td>' + '\n'
        info += '<td class="td_date">' + mail_time + '</td>' + '\n'
        info += '</tr>' + '\n\n'

        if mail_date not in info_by_date:
            info_by_date[mail_date] = []

        info_by_date[mail_date].append(info)

    for _date in sorted(list(info_by_date.keys()), reverse=True):
        quar_mail_info += '<tr class="tr_date"><td colspan="4">' + _date + '</td></tr>' + '\n'
        for r in info_by_date[_date]:
            quar_mail_info += r

    msg = MIMEMultipart('alternative')

    msg['Subject'] = Header(mail_subject % {'total': total}, 'utf-8')
    msg['To'] = user

    if settings.NOTIFICATION_SENDER_NAME:
        msg['From'] = '{} <{}>'.format(Header(settings.NOTIFICATION_SENDER_NAME, 'utf-8'), smtp_user)
    else:
        msg['From'] = Header(smtp_user, 'utf-8')

    mail_body = mail_body_template % {'quar_mail_info': quar_mail_info,
                                      'quar_keep_days': settings.AMAVISD_REMOVE_QUARANTINED_IN_DAYS,
                                      'iredadmin_url': iredadmin_url,
                                      'timezone': settings.LOCAL_TIMEZONE}

    # HTML email must contain text and html part with same content, otherwise
    # it will be considered as not well-formated email.
    body_part_plain = MIMEText(mail_body, 'plain', 'utf-8')
    msg.attach(body_part_plain)

    body_part_html = MIMEText(mail_body, 'html', 'utf-8')
    msg.attach(body_part_html)

    msg_string = msg.as_string()

    ret = iredutils.sendmail(recipients=user, message_text=msg_string)
    if ret[0]:
        logger.info('+ %s: %d mails.' % (user, total))
    else:
        logger.info('+ << ERROR >> Error while sending notification email to {}: {}'.format(user, ret[1]))

# Log last notify time.
conn_iredadmin.delete('tracking', where="k='quarantine_notify_time'")
conn_iredadmin.insert('tracking', k='quarantine_notify_time', v=now)
