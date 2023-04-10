# Author: Zhang Huangbin <zhb@iredmail.org>

import web

import settings
from controllers.utils import api_render

from libs import form_utils, iredpwd
from libs.logger import log_activity
from libs.sqllib import SQLWrap, decorators
from libs.sqllib import user as sql_lib_user
from libs.sqllib import admin as sql_lib_admin
from libs.sqllib import general as sql_lib_general
from libs.sqllib import api_utils

session = web.config.get('_session')


class APIUser:
    @decorators.api_require_domain_access
    def GET(self, mail):
        """Export SQL record of mail user as a dict.

        curl -X GET -i -b cookie.txt https://<server>/api/user/<mail>
        """
        mail = str(mail).lower()

        _wrap = SQLWrap()
        conn = _wrap.conn

        qr = sql_lib_user.profile(mail=mail,
                                  with_aliases=True,
                                  with_alias_groups=True,
                                  with_mailing_lists=True,
                                  with_forwardings=True,
                                  with_used_quota=True,
                                  with_last_login=True,
                                  conn=conn)
        if qr[0]:
            profile = api_utils.export_sql_record(record=qr[1],
                                                  remove_columns=settings.API_HIDDEN_USER_PROFILES)

            if profile.get('isadmin') == 1:
                # Get all managed domains
                _qr = sql_lib_admin.get_managed_domains(admin=mail,
                                                        domain_name_only=True,
                                                        listed_only=True,
                                                        conn=conn)
                if _qr[0]:
                    profile['managed_domains'] = _qr[1]

            return api_render((True, profile))
        else:
            return api_render(qr)

    @decorators.api_require_domain_access
    def POST(self, mail):
        """Create a new mail user.

        curl -X POST -i -b cookie.txt -d "var=value1&var2=value2&..." https://<server>/api/user/<mail>

        Optional POST data:

        @name - display name
        @password - password
        @password_hash - password hash
        @language - default preferred language for new user. e.g.
                    en_US for English, de_DE for Deutsch.
        @quota - mailbox quota for this user (in MB).
        """
        mail = str(mail).lower()
        (username, domain) = mail.split('@', 1)

        if not session.get('is_global_admin'):
            sql_lib_user.redirect_if_user_is_global_admin(conn=None, mail=mail)

        form = web.input()

        form['username'] = username
        form['domainName'] = domain

        form['preferredLanguage'] = form.get('language')
        form['cn'] = form.get('name')

        _pw = form.get('password', '')
        if _pw:
            form['newpw'] = _pw
            form['confirmpw'] = _pw
        else:
            _pw_hash = form.get('password_hash', '')
            form['password_hash'] = _pw_hash

        # Set quota
        form['mailQuota'] = form.get('quota')

        qr = sql_lib_user.add_user_from_form(domain=domain, form=form)
        return api_render(qr)

    @decorators.api_require_domain_access
    def DELETE(self, mail, keep_mailbox_days=0):
        """Delete a mail user.

        curl -X DELETE -i -b cookie.txt https://<server>/api/user/<mail>
        curl -X DELETE -i -b cookie.txt https://<server>/api/user/<mail>/keep_mailbox_days/<days>
        """
        mail = str(mail).lower()

        _wrap = SQLWrap()
        conn = _wrap.conn

        if not session.get('is_global_admin'):
            sql_lib_user.redirect_if_user_is_global_admin(conn=conn, mail=mail)

        qr = sql_lib_user.delete_users(conn=conn, accounts=[mail], keep_mailbox_days=keep_mailbox_days)
        return api_render(qr)

    @decorators.api_require_domain_access
    def PUT(self, mail):
        """Update user profile.

        curl -X PUT -i -b cookie.txt -d "var=<value>" https://<server>/api/user/<mail>
        curl -X PUT -i -b cookie.txt -d "var=<value>&var2=<value2>" https://<server>/api/user/<mail>

        Optional PUT data:

        @name - common name (or, display name)
        @password - set new password for user
        @password_hash - set new password to given hashed password
        @quota - mailbox quota for this user (in MB).
        @accountStatus - enable or disable user. possible value is: active, disabled.
        @language - set preferred language of web UI
        @employeeid - set employee id
        @transport - set per-user transport
        @isGlobalAdmin -- promote user to be a global admin
        @forwarding -- set per-user mail forwarding addresseses
        @addForwarding -- add per-user mail forwarding addresses
        @removeForwarding -- remove existing per-user mail forwarding addresses
        @senderBcc -- set per-user bcc for outbound emails
        @recipientBcc -- set per-user bcc for inbound emails
        @aliases -- reset per-user alias addresses
        @addAlias -- add new per-user alias addresses
        @removeAlias -- remove existing per-user alias addresses
        @maildir -- full maildir path of the mailbox
        """
        mail = str(mail).lower()
        form = web.input()
        qr = sql_lib_user.api_update_profile(mail=mail, form=form, conn=None)
        return api_render(qr)


class APIUsers:
    @decorators.api_require_domain_access
    def GET(self, domain):
        """List all mail users in given domain.

        curl -X GET -i -b cookie.txt https://<server>/api/users/<domain>

        Optional parameters:

        @email_only -- return a list of users' email addresses.
                       if not present, return a list of user profiles
                       (dicts).
        @disabled_only -- return disabled users.
        """
        domain = str(domain).lower()

        form = web.input(_unicode=True)
        email_only = ('email_only' in form)
        disabled_only = ('disabled_only' in form)

        qr = sql_lib_user.get_basic_user_profiles(domain=domain,
                                                  email_only=email_only,
                                                  disabled_only=disabled_only,
                                                  with_last_login=True,
                                                  with_used_quota=True,
                                                  conn=None)

        if qr[0]:
            if email_only:
                emails = qr[1]
                return api_render((True, emails))
            else:
                profiles = api_utils.export_sql_records(records=qr[1])
                return api_render((True, profiles))
        else:
            return api_render(qr)

    @decorators.api_require_domain_access
    def PUT(self, domain):
        """Update profiles of users under domain.

        curl -X PUT -i -b cookie.txt -d "var=<value>" https://<server>/api/users/<domain>
        curl -X PUT -i -b cookie.txt -d "var=<value>&var2=<value2>" https://<server>/api/users/<domain>

        Optional PUT data:

        @name - common name (or, display name)
        @accountStatus - enable or disable user. possible value is: active, disabled.
        @language - set preferred language of web UI
        @transport - set per-user transport
        @password - reset all users' password.
        """
        domain = str(domain).lower()

        form = web.input()
        params = {}

        # Name
        kv = form_utils.get_form_dict(form,
                                      input_name='name',
                                      key_name='name')
        params.update(kv)

        # Account status
        kv = form_utils.get_form_dict(form,
                                      input_name='accountStatus',
                                      key_name='active')
        params.update(kv)

        # Language
        kv = form_utils.get_form_dict(form,
                                      input_name='language',
                                      to_string=True)
        params.update(kv)

        # Transport
        kv = form_utils.get_form_dict(form,
                                      input_name='transport',
                                      to_string=True)
        params.update(kv)

        _wrap = SQLWrap()
        conn = _wrap.conn

        # Password
        if "password" in form:
            pw = form_utils.get_single_value(form,
                                             input_name="password",
                                             default_value="",
                                             to_string=True)

            if not pw:
                return api_render((False, "EMPTY_PASSWORD"))

            qr = sql_lib_general.get_domain_settings(domain=domain, conn=conn)
            if not qr[0]:
                return api_render(qr)

            ds = qr[1]
            min_passwd_length = ds.get('min_passwd_length', settings.min_passwd_length)
            max_passwd_length = ds.get('max_passwd_length', settings.max_passwd_length)

            qr = iredpwd.verify_new_password(newpw=pw,
                                             confirmpw=pw,
                                             min_passwd_length=min_passwd_length,
                                             max_passwd_length=max_passwd_length)
            if qr[0]:
                params["password"] = iredpwd.generate_password_hash(pw)
            else:
                return api_render(qr)

        if not params:
            return api_render(True)

        try:

            conn.update('mailbox',
                        vars={'domain': domain},
                        where='domain=$domain',
                        **params)

            try:
                # Log updated parameters and values if possible
                msg = str(params)
            except:
                msg = ', '.join(params)

            log_activity(msg="Update profiles of all users under domain: {} -> {}".format(domain, msg),
                         admin=session.get('username'),
                         username=domain,
                         domain=domain,
                         event='update')

            return api_render(True)
        except Exception as e:
            return api_render((False, repr(e)))


class APIUsersPassword:
    @decorators.api_require_domain_access
    def PUT(self, domain):
        """Update password of all users under domain.

        curl -X PUT -i -b cookie.txt -d "var=<value>" https://<server>/api/users/<domain>/password

        Required parameters:

        @password - set new password for user
        """
        domain = str(domain).lower()

        form = web.input()

        qr = api_utils.get_form_password_dict(form=form,
                                              domain=domain,
                                              input_name='password')
        if qr[0]:
            pw_hash = qr[1]['pw_hash']

            _wrap = SQLWrap()
            conn = _wrap.conn

            conn.update('mailbox',
                        vars={'domain': domain},
                        where='domain=$domain',
                        password=pw_hash)

            log_activity(msg="Update all users' password under domain: %s" % domain,
                         admin=session.get('username'),
                         username=domain,
                         domain=domain,
                         event='update')

            return api_render(True)
        else:
            return api_render(qr)


class APIChangeEmail:
    @decorators.api_require_domain_access
    def POST(self, mail, new_mail):
        """Change user email address.

        curl -X POST -i -b cookie.txt https://<server>/api/user/<mail>/change_email/<new_mail>
        """
        mail = str(mail).lower()
        new_mail = str(new_mail).lower()

        qr = sql_lib_user.change_email(mail=mail, new_mail=new_mail)
        return api_render(qr)
