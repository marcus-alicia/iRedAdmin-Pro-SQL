# Author: Zhang Huangbin <zhb@iredmail.org>

import time
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.header import Header
import web

from libs import iredutils
from libs.logger import logger
from libs.mlmmj import add_subscribers, remove_subscribers
import settings

if settings.backend == 'ldap':
    from libs.ldaplib.ml import get_profile_by_mlid
else:
    from libs.sqllib.ml import get_profile_by_mlid


base_url = web.ctx.homedomain + settings.NEWSLETTER_BASE_URL


class Error:
    """Display error messages happened during subscription/unsubscription."""
    def GET(self):
        form = web.input(_unicode=False)
        msg = form.get('msg')
        return web.render('mlmmj/errors.html', msg=msg)


# SubUnsubSSR returns HTML snippet to requester directly.
class SubUnsubSSR:
    def OPTIONS(self, action, mlid):
        # These headers are used when HTTP POST requests are sent from web page
        # running on another domain.
        web.header("Access-Control-Allow-Origin", "*")
        web.header("Access-Control-Allow-Headers", "*")
        web.header("Access-Control-Allow-Methods", "POST")
        return ""

    def POST(self, action, mlid):
        web.header("Access-Control-Allow-Origin", "*")

        if action not in ['subscribe']:
            return "INVALID_ACTION"

        form = web.input(_unicode=False)
        subscriber = form.get('subscriber', '').lower()

        if not iredutils.is_email(subscriber):
            return "Invalid email address."

        # Get newsletter profile
        qr = get_profile_by_mlid(mlid=mlid)
        if not qr[0]:
            return "Invalid newsletter."

        profile = qr[1]
        if settings.backend == 'ldap':
            mail = profile['mail'][0]
            name = profile.get('cn', [''])[0]
        else:
            mail = profile['address']
            name = profile['name']

        # Generate an unique string as verification token
        token = iredutils.generate_random_strings(length=32)

        # Set expire date for this subscription request
        if action == 'subscribe':
            _expire_hours = settings.NEWSLETTER_SUBSCRIPTION_REQUEST_EXPIRE_HOURS
        else:
            _expire_hours = settings.NEWSLETTER_UNSUBSCRIPTION_REQUEST_EXPIRE_HOURS

        expire_date = int(time.time()) + (int(_expire_hours) * 60 * 60)

        #
        # Store this subscription request in sql db.
        #
        try:
            # Delete existing subscription confirm.
            web.conn_iredadmin.delete(
                'newsletter_subunsub_confirms',
                vars={
                    'mlid': mlid,
                    'subscriber': subscriber,
                    'kind': action,
                },
                where='mlid=$mlid AND subscriber=$subscriber AND kind=$kind',
            )

            # Insert a new record
            web.conn_iredadmin.insert(
                'newsletter_subunsub_confirms',
                mail=mail,
                mlid=mlid,
                subscriber=subscriber,
                kind=action,
                token=token,
                expired=expire_date,
            )

        except Exception as e:
            logger.error(e)
            return "Internal server error, please try again later."

        #
        # Send confirm email
        #
        # Generate mail message
        _msg = MIMEMultipart('alternative')

        # Set mailing list address as sender in `From:`
        _smtp_sender = mail
        _smtp_sender_name = settings.NOTIFICATION_SENDER_NAME
        if _smtp_sender_name:
            _msg['From'] = '{} <{}>'.format(Header(_smtp_sender_name, 'utf-8'), _smtp_sender)
        else:
            _msg['From'] = _smtp_sender

        _msg['To'] = subscriber

        if action == 'subscribe':
            _msg_subject = 'Subscription confirm'
            _subunsub_url = base_url + '/subconfirm/{}/{}'.format(mlid, token)
        else:
            _msg_subject = 'Unsubscription confirm'
            _subunsub_url = base_url + '/unsubconfirm/{}/{}'.format(mlid, token)

        # Add mailing list name.
        if name:
            _msg_subject += ': ' + name

        _msg['Subject'] = Header(_msg_subject, 'utf-8')

        if action == 'subscribe':
            _msg_body = 'Please click link below to confirm subscription to newsletter'
        else:
            _msg_body = 'Please click link below to confirm unsubscription from newsletter'

        if name:
            _msg_body += ' "' + name + '"'

        _msg_body += ':\n' + _subunsub_url + '\n'
        _msg_body += '\nLink will expire in %d hours.' % settings.NEWSLETTER_SUBSCRIPTION_REQUEST_EXPIRE_HOURS
        _msg_body += '\nIf this is not requested by you, please simply ignore this email.'

        _msg_body_plain = MIMEText(_msg_body, 'plain', 'utf-8')
        _msg.attach(_msg_body_plain)

        _msg_string = _msg.as_string()

        qr = iredutils.sendmail(
            recipients=subscriber,
            message_text=_msg_string,
            from_address=_smtp_sender,
        )
        if qr[0]:
            if action == 'subscribe':
                return "Almost done, an email has been sent to the address, please click the link in email to confirm the subscription."
            else:
                return "Almost done, an email has been sent to the address, please click the link in email to unsubscribe."
        else:
            return qr[1]


class SubUnsub:
    """Handle the subscription and unsubscription."""
    def GET(self, action, mlid):
        if action not in ['subscribe', 'unsubscribe']:
            raise web.seeother(base_url + '/error?msg=INVALID_ACTION', absolute=True)

        # Display a subscription form.
        form = web.input(_unicode=False)
        msg = form.get('msg')

        # Get newsletter profile
        qr = get_profile_by_mlid(mlid=mlid)
        if not qr[0]:
            raise web.seeother(base_url + '/error?msg=INVALID_NEWSLETTER', absolute=True)

        profile = qr[1]

        # Get display name and description
        if settings.backend == 'ldap':
            name = profile.get('cn', [''])[0]
            description = profile.get('description', [''])[0]
        else:
            name = profile['name']
            description = profile['description']

        # Get basic newsletter info: display name, short introduction.
        return web.render('mlmmj/subunsub.html',
                          action=action,
                          mlid=mlid,
                          name=name,
                          description=description,
                          msg=msg)

    def POST(self, action, mlid):
        if action not in ['subscribe', 'unsubscribe']:
            raise web.seeother(base_url + '/error?msg=INVALID_ACTION', absolute=True)

        form = web.input(_unicode=False)
        subscriber = form.get('subscriber', '').lower()

        if not iredutils.is_email(subscriber):
            raise web.seeother(base_url + '/error?msg=INVALID_SUBSCRIBER_EMAIL_ADDRESS', absolute=True)

        # Get newsletter profile
        qr = get_profile_by_mlid(mlid=mlid)
        if not qr[0]:
            raise web.seeother(base_url + '/error?msg=INVALID_NEWSLETTER', absolute=True)

        profile = qr[1]
        if settings.backend == 'ldap':
            mail = profile['mail'][0]
            name = profile.get('cn', [''])[0]
        else:
            mail = profile['address']
            name = profile['name']

        # Generate an unique string as verification token
        token = iredutils.generate_random_strings(length=32)

        # Set expire date for this subscription request
        if action == 'subscribe':
            _expire_hours = settings.NEWSLETTER_SUBSCRIPTION_REQUEST_EXPIRE_HOURS
        else:
            _expire_hours = settings.NEWSLETTER_UNSUBSCRIPTION_REQUEST_EXPIRE_HOURS

        expire_date = int(time.time()) + (int(_expire_hours) * 60 * 60)

        #
        # Store this subscription request in sql db.
        #
        try:
            # Delete existing subscription confirm.
            web.conn_iredadmin.delete(
                'newsletter_subunsub_confirms',
                vars={'mlid': mlid, 'subscriber': subscriber, 'kind': action},
                where='mlid=$mlid AND subscriber=$subscriber AND kind=$kind',
            )

            # Insert a new record
            web.conn_iredadmin.insert(
                'newsletter_subunsub_confirms',
                mail=mail,
                mlid=mlid,
                subscriber=subscriber,
                kind=action,
                token=token,
                expired=expire_date,
            )

        except Exception as e:
            logger.error(e)
            raise web.seeother(base_url + '/error?msg=INTERNAL_SERVER_ERROR', absolute=True)

        #
        # Send confirm email
        #
        # Generate mail message
        _msg = MIMEMultipart('alternative')

        # Set mailing list address as sender in `From:`
        _smtp_sender = mail
        _smtp_sender_name = settings.NOTIFICATION_SENDER_NAME
        if _smtp_sender_name:
            _msg['From'] = '{} <{}>'.format(Header(_smtp_sender_name, 'utf-8'), _smtp_sender)
        else:
            _msg['From'] = _smtp_sender

        _msg['To'] = subscriber

        if action == 'subscribe':
            _msg_subject = 'Subscription confirm'
            _subunsub_url = base_url + '/subconfirm/{}/{}'.format(mlid, token)
        else:
            _msg_subject = 'Unsubscription confirm'
            _subunsub_url = base_url + '/unsubconfirm/{}/{}'.format(mlid, token)

        # Add mailing list name.
        if name:
            _msg_subject += ': ' + name

        _msg['Subject'] = Header(_msg_subject, 'utf-8')

        if action == 'subscribe':
            _msg_body = 'Please click link below to confirm subscription to newsletter'
        else:
            _msg_body = 'Please click link below to confirm unsubscription from newsletter'

        if name:
            _msg_body += ' "' + name + '"'

        _msg_body += ':\n' + _subunsub_url + '\n'
        _msg_body += '\nLink will expire in %d hours.' % settings.NEWSLETTER_SUBSCRIPTION_REQUEST_EXPIRE_HOURS
        _msg_body += '\nIf this is not requested by you, please simply ignore this email.'

        _msg_body_plain = MIMEText(_msg_body, 'plain', 'utf-8')
        _msg.attach(_msg_body_plain)

        _msg_string = _msg.as_string()

        qr = iredutils.sendmail(
            recipients=subscriber,
            message_text=_msg_string,
            from_address=_smtp_sender,
        )
        if qr[0]:
            if action == 'subscribe':
                raise web.seeother(base_url + '/subscribe/%s?msg=WAIT_FOR_SUBCONFIRM' % mlid, absolute=True)
            else:
                raise web.seeother(base_url + '/unsubscribe/%s?msg=WAIT_FOR_UNSUBCONFIRM' % mlid, absolute=True)
        else:
            raise web.seeother(base_url + '/error?msg=%s' % web.urlquote(qr[1]), absolute=True)


class SubUnsubConfirm:
    """Process subscription confirm."""
    def GET(self, action, mlid, token):
        if action == 'subconfirm':
            action = 'subscribe'
        elif action == 'unsubconfirm':
            action = 'unsubscribe'
        else:
            raise web.seeother(base_url + '/error?msg=INVALID_ACTION', absolute=True)

        if not iredutils.is_mlid(mlid):
            raise web.seeother(base_url + '/error?msg=INVALID_NEWSLETTER', absolute=True)

        if not iredutils.is_ml_confirm_token(token):
            raise web.seeother(base_url + '/error?msg=TOKEN_INVALID', absolute=True)

        _record = {}

        try:
            now = int(time.time())

            qr = web.conn_iredadmin.select(
                'newsletter_subunsub_confirms',
                vars={'mlid': mlid, 'token': token, 'kind': action, 'now': now},
                what='mail, mlid, subscriber',
                where='mlid=$mlid AND token=$token AND kind=$kind AND expired >= $now',
                limit=1,
            )

            qr = list(qr)
            if qr:
                _record = qr[0]
        except Exception as e:
            raise web.seeother(base_url + '/error?msg=%s' % web.urlquote(repr(e)), absolute=True)

        if not _record:
            raise web.seeother(base_url + '/error?msg=TOKEN_EXPIRED', absolute=True)

        _mail = str(_record['mail']).lower()
        _subscriber = str(_record['subscriber']).lower()

        # Subscribe this subscriber
        if action == 'subscribe':
            qr = add_subscribers(mail=_mail,
                                 subscribers=[_subscriber],
                                 require_confirm=False)
        else:
            qr = remove_subscribers(mail=_mail, subscribers=[_subscriber])

        if not qr[0]:
            raise web.seeother(base_url + '/error?msg=%s' % web.urlquote(qr[1]), absolute=True)

        try:
            # Update the record expire time, instead of deleting the record.
            now = int(time.time())
            web.conn_iredadmin.update(
                'newsletter_subunsub_confirms',
                vars={'mlid': mlid, 'token': token, 'kind': action},
                expired=now,
                where='mlid=$mlid AND token=$token AND kind=$kind',
            )
        except Exception as e:
            raise web.seeother(base_url + '/error?msg=%s' % web.urlquote(repr(e)), absolute=True)

        if action == 'subscribe':
            raise web.seeother(base_url + '/subscribe/%s?msg=SUBSCRIBED' % mlid, absolute=True)
        else:
            raise web.seeother(base_url + '/unsubscribe/%s?msg=UNSUBSCRIBED' % mlid, absolute=True)
