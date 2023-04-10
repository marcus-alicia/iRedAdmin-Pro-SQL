# Author: Zhang Huangbin <zhb@iredmail.org>

import socket
import web
import settings
from libs import iredutils
from libs.amavisd import QUARANTINE_TYPES

session = web.config.get("_session")

# Import backend related modules.
if settings.backend == "ldap":
    from libs.ldaplib.admin import get_managed_domains
elif settings.backend in ["mysql", "pgsql"]:
    from libs.sqllib.admin import get_managed_domains


def get_raw_message(mail_id: str) -> bytes:
    """Get raw mail message of quarantined email specified by `mail_id`."""
    # TODO Check domain access by sender/recipient of quarantined email
    if not mail_id:
        return False, "INVALID_MAILID"

    try:
        records = web.conn_amavisd.select(
            "quarantine",
            vars={"mail_id": mail_id},
            what="mail_text",
            where="mail_id=$mail_id",
            order="chunk_ind ASC",
        )

        if not records:
            return False, "INVALID_MAILID"

        # Combine mail_text as RAW mail message.
        # Note: `mail_text` is bytes type.
        message = b""
        records = list(records)
        for i in records:
            message += i['mail_text']

        return True, message
    except Exception as e:
        return False, repr(e)


# If msgs.quar_type != "Q" (SQL), we can't get mail body.
def get_quarantined_mails(page=1,
                          account_type=None,
                          account="",
                          quarantined_type="",
                          size_limit=settings.PAGE_SIZE_LIMIT,
                          sort_by_score=False):
    """Return ([True | False], (total, records))"""

    page = int(page)
    account = str(account) or None

    # Pre-defined values.
    count = 0
    records = []
    sql_append_selection = ''

    # Domain names under control.
    all_domains = []

    # Query SQL.
    if session.get('is_normal_admin'):
        # List all managed domains in query if admin is not global admin
        qr = get_managed_domains(admin=session.get('username'), domain_name_only=True)
        if qr[0]:
            all_domains = qr[1]

        all_reversed_domains = iredutils.reverse_amavisd_domain_names(all_domains)

        if all_domains:
            sql_append_selection += ' AND (sender.domain IN {} OR recip.domain IN {})'.format(
                web.sqlquote(all_reversed_domains),
                web.sqlquote(all_reversed_domains),
            )
        else:
            return True, (0, {})

    if account_type == 'domain':
        if account:
            reversed_account = iredutils.reverse_amavisd_domain_names([account])[0]

            if not session.get('is_global_admin'):
                # Make sure account is managed domain
                if account not in all_domains:
                    # PERMISSION_DENIED
                    return True, (0, {})

            sql_append_selection += ' AND (sender.domain={} OR recip.domain={})'.format(
                web.sqlquote(reversed_account), web.sqlquote(reversed_account),
            )
    elif account_type == 'user':
        if session.get('is_normal_admin'):
            # Make sure account is under managed domains
            if not account.split('@', 1)[-1] in all_domains:
                # PERMISSION_DENIED
                return True, (0, {})
        elif session.get('account_is_mail_user'):
            if account != session['username']:
                return True, (0, {})

        sql_append_selection += ' AND (sender.email={} OR recip.email={})'.format(
            web.sqlquote(account),
            web.sqlquote(account),
        )

    if quarantined_type == 'spam':
        sql_append_selection += " AND msgs.content IN ('S', 's', 'Y')"
    elif quarantined_type == 'virus':
        sql_append_selection += " AND msgs.content = 'V'"
    elif quarantined_type == 'banned':
        sql_append_selection += " AND msgs.content = 'B'"
    elif quarantined_type == 'badheader':
        sql_append_selection += " AND msgs.content = 'H'"
    elif quarantined_type == 'badmime':
        sql_append_selection += " AND msgs.content = 'M'"

    # Get number of total records. SQL table: amavisd.msgs
    try:
        # Refer to templates/default/macros/amavisd.html for more detail
        # about msgs.content (content type, spam status), msgs.quar_type
        # (quarantine type).
        result = web.conn_amavisd.query(
            """
            -- Get number of quarantined emails
            SELECT COUNT(msgs.mail_id) AS total
            FROM msgs
            LEFT JOIN msgrcpt ON msgs.mail_id = msgrcpt.mail_id
            LEFT JOIN maddr AS sender ON msgs.sid = sender.id
            LEFT JOIN maddr AS recip ON msgrcpt.rid = recip.id
            WHERE
                -- msgs.content IN ('S', 's', 'Y', 'V', 'B', 'H')
                -- AND msgs.quar_type = 'Q'
                msgs.quar_type = 'Q'
                %s
            """ % sql_append_selection)

        count = result[0].total or 0
    except:
        pass

    # Get records of quarantined mails.
    try:
        # msgs.content:
        #   - S: spam(kill)
        #   - s: prior to 2.7.0 the CC_SPAMMY was logged as 's', now 'Y' is used.
        # msgs.quar_type:
        #   - Q: sql
        #   - F: file
        sort_column = 'msgs.time_num'
        if sort_by_score:
            sort_column = 'msgs.spam_level'

        result = web.conn_amavisd.query(
            '''
            -- Get records of quarantined mails.
            SELECT
                msgs.mail_id, msgs.secret_id, msgs.subject, msgs.time_num,
                msgs.content, msgs.size, msgs.spam_level,
                sender.email AS sender_email,
                recip.email AS recipient
            FROM msgs
            LEFT JOIN msgrcpt ON msgs.mail_id = msgrcpt.mail_id
            LEFT JOIN maddr AS sender ON msgs.sid = sender.id
            LEFT JOIN maddr AS recip ON msgrcpt.rid = recip.id
            WHERE
                -- msgs.content IN ('S', 's', 'Y', 'V', 'B', 'H')
                -- AND msgs.quar_type = 'Q'
                msgs.quar_type = 'Q'
                %s
            ORDER BY %s DESC
            LIMIT %d
            OFFSET %d
            ''' % (sql_append_selection, sort_column, size_limit, (page - 1) * size_limit)
        )
        records = iredutils.bytes2str(result)
    except:
        pass

    return True, (count, records)


def delete_all_quarantined(quarantined_type=None):
    if quarantined_type in QUARANTINE_TYPES:
        _content = QUARANTINE_TYPES[quarantined_type]

        # Delete them from `msgs`.
        # Records in `quarantine` will be cleaned up by cron job
        try:
            web.conn_amavisd.delete(
                'msgs',
                vars={'quar_type': 'Q', 'content': _content},
                where='quar_type=$quar_type AND content=$content',
            )
            return True,
        except Exception as e:
            return False, repr(e)
    else:
        try:
            web.conn_amavisd.delete('quarantine', where='1=1')
            web.conn_amavisd.delete('msgs', where="""quar_type='Q'""")
            return True,
        except Exception as e:
            return False, repr(e)


def release_quarantined_mails(records=None):
    # Release quarantined mails.
    #
    # records = [
    #    {'mail_id': 'xxx',
    #     'secret_id': 'yyy',
    #     'requested_by': session.get('username'),
    #    },
    #    [],
    # ]
    #
    # Refer to amavisd doc 'README.protocol' for more detail:
    #   - Releasing a message from a quarantine

    if not records:
        return True,

    # TODO Check domain_access
    #   - Get managed domains.
    #   - Check whether mail_id in `records` are one of managed domains.
    #   - Get allowed mail_id list.

    # Pre-defined variables.
    released_mail_ids = []

    # Create socket.
    try:
        quar_server = settings.amavisd_db_host
        quar_port = int(settings.amavisd_quarantine_port)

        if settings.AMAVISD_QUARANTINE_HOST:
            quar_server = settings.AMAVISD_QUARANTINE_HOST

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((quar_server, quar_port))
    except Exception as e:
        return False, repr(e)

    # Generate commands from dict, used for socket communication.
    # Note: We need to update Amavisd SQL database after mail was released
    #       with success, so do NOT send all release requests in ONE socket
    #       command although it will get better performance (a little).
    for record in records:
        # Skip record without 'mail_id'.
        if 'mail_id' not in record:
            continue

        cmd_release = 'request=release\r\n'

        for k in record:
            if record[k] is not None and record[k] != '':
                cmd_release += '{}={}\r\n'.format(k, record[k])

        cmd_release += 'quar_type=Q\r\n\r\n'
        try:
            s.send(cmd_release.encode())

            # Must wait for Amavisd's response before deleting SQL record,
            # otherwise we may delete sql record BEFORE Amavisd releases
            # quarantined email.
            s.recv(1024)

            released_mail_ids += [record.get('mail_id', 'NOT-EXIST')]
        except Exception as e:
            return False, repr(e)

    # Close socket.
    try:
        s.close()
    except Exception as e:
        return False, repr(e)

    # Return if no record was released successfully.
    if len(released_mail_ids) == 0:
        return True,

    # Update Amavisd SQL database.
    try:
        #   - Update msgs.content to 'C' (Clean)
        #       UPDATE msgs \
        #       SET msgs.content = 'C' \
        #       WHERE msgs.mail_id IN ('xxx', 'yyy', ..)
        #
        #   - Delete records in 'quarantine':
        #       DELETE FROM quarantine \
        #       WHERE quarantine.partition_tag = msgs.partition_tag \
        #       AND quarantine.mail_id = msgs.mail_id
        #
        web.conn_amavisd.update(
            'msgs',
            where='mail_id IN ' + web.sqlquote(released_mail_ids),
            quar_type='',
            content='C',
        )

        web.conn_amavisd.delete(
            'quarantine',
            where='mail_id IN ' + web.sqlquote(released_mail_ids),
        )

        return True,
    except Exception as e:
        return False, repr(e)
