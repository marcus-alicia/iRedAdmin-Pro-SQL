# Author: Zhang Huangbin <zhb@iredmail.org>

import web

from controllers.utils import api_render

from libs import iredutils, form_utils
from libs.logger import log_activity
from libs.sqllib import SQLWrap, decorators
from libs.sqllib import general as sql_lib_general
from libs.sqllib import alias as sql_lib_alias
from libs.sqllib import api_utils

session = web.config.get('_session')


class APIAlias:
    @decorators.api_require_domain_access
    def GET(self, mail):
        """Export mail alias profile.

        curl -X GET -i -b cookie.txt https://<server>/api/alias/<mail>
        """
        mail = str(mail).lower()
        qr = sql_lib_alias.get_profile(mail=mail, conn=None)
        if qr[0]:
            profile = api_utils.export_sql_record(record=qr[1])
            return api_render((True, profile))
        else:
            return api_render(qr)

    @decorators.api_require_domain_access
    def POST(self, mail):
        """Create a new mail alias account.

        curl -X POST -i -b cookie.txt -d "..." https://<server>/api/alias/<email>

        Optional POST data:

        @name - display name
        @accessPolicy - access policy
        @members - members of mail alias
        """
        mail = str(mail).lower()
        (listname, domain) = mail.split('@', 1)

        form = web.input()

        form['listname'] = listname
        form['domainName'] = domain

        form['cn'] = form.get('name')

        qr = sql_lib_alias.add_alias_from_form(domain=domain, form=form)

        if qr[0] and 'members' in form:
            # Update mail forwarding addresses
            _addresses = form_utils.get_multi_values_from_api(form=form,
                                                              input_name='members',
                                                              to_lowercase=False,
                                                              is_email=True)
            _qr = sql_lib_alias.reset_members(mail=mail, members=_addresses)
            return api_render(_qr)

        return api_render(qr)

    # Delete aliases.
    @decorators.api_require_domain_access
    def DELETE(self, mail):
        """Delete a mail alias account.
        curl -X DELETE -i -b cookie.txt https://<server>/api/alias/<mail>
        """
        mail = str(mail).lower()
        qr = sql_lib_alias.delete_aliases(accounts=[mail])
        return api_render(qr)

    @decorators.api_require_domain_access
    def PUT(self, mail):
        """Update profile of existing mail alias account.

        curl -X PUT -i -b cookie.txt -d "var=<value>" https://<server>/api/alias/<mail>
        curl -X PUT -i -b cookie.txt -d "var=<value>&var2=<value2>" https://<server>/api/alias/<mail>

        Optional PUT data:

        @name - common name (or, display name)
        @accountStatus - enable or disable user. possible value is: active, disabled.
        @accessPolicy - access policy.
        @members - members of mail alias
        @addMember - add new members to mailing list
        @removeMember - remove members from mailing list
        """
        mail = str(mail).lower()
        domain = mail.split('@', 1)[-1]

        form = web.input()

        params = {}

        # Name
        kv = form_utils.get_form_dict(form,
                                      input_name='name',
                                      key_name='name',
                                      default_value='')
        params.update(kv)

        # accountStatus
        kv = form_utils.get_form_dict(form,
                                      input_name='accountStatus',
                                      key_name='active',
                                      default_value='1')
        params.update(kv)

        # Access policy
        kv = form_utils.get_form_dict(form,
                                      input_name='accessPolicy',
                                      key_name='accesspolicy',
                                      default_value='public')
        params.update(kv)

        # Reset all members
        _members = []

        # Add new members
        _new = []

        # Remove existing members
        _removed = []

        if 'members' in form:
            # Update mail forwarding addresses
            _v = form_utils.get_multi_values_from_api(form=form,
                                                      input_name='members',
                                                      to_lowercase=False,
                                                      is_email=True)
            _members = [iredutils.lower_email_with_upper_ext_address(i) for i in _v]

        else:
            if 'addMember' in form:
                _v = form_utils.get_multi_values_from_api(form=form,
                                                          input_name='addMember',
                                                          to_lowercase=False,
                                                          is_email=True)
                _new = [iredutils.lower_email_with_upper_ext_address(i) for i in _v]

            if 'removeMember' in form:
                _v = form_utils.get_multi_values_from_api(form=form,
                                                          input_name='removeMember',
                                                          to_lowercase=False,
                                                          is_email=True)
                _removed = [iredutils.lower_email_with_upper_ext_address(i) for i in _v]

        if not (params or ('members' in form) or _new or _removed):
            return api_render(True)

        _wrap = SQLWrap()
        conn = _wrap.conn

        if not sql_lib_general.is_alias_exists(mail=mail, conn=conn):
            return api_render((False, 'NO_SUCH_ACCOUNT'))

        if params:
            try:
                conn.update('alias',
                            vars={'mail': mail},
                            where='address=$mail',
                            **params)

                log_activity(msg="Update alias profile: {} -> {}".format(mail, ', '.join(params)),
                             admin=session.get('username'),
                             username=mail,
                             domain=domain,
                             event='update')

            except Exception as e:
                return api_render((False, repr(e)))

        if 'members' in form:
            qr = sql_lib_alias.reset_members(mail=mail, members=_members, conn=conn)

            if not qr[0]:
                return api_render(qr)

        if _new or _removed:
            qr = sql_lib_alias.update_members(mail=mail,
                                              new_members=_new,
                                              removed_members=_removed,
                                              conn=conn)

            if not qr[0]:
                return api_render(qr)

        return api_render(True)


class APIChangeEmail:
    @decorators.api_require_domain_access
    def POST(self, mail, new_mail):
        """Change email address of mail alias account.

        curl -X POST -i -b cookie.txt https://<server>/api/alias/<mail>/change_email/<new_mail>
        """
        mail = str(mail).lower()
        new_mail = str(new_mail).lower()

        qr = sql_lib_alias.change_email(mail=mail, new_mail=new_mail)
        return api_render(qr)


class APIAliases:
    @decorators.api_require_domain_access
    def GET(self, domain):
        """List all mail aliases under given domain.

        curl -X GET -i -b cookie.txt https://<server>/api/aliases/<domain>

        Optional parameters:

        @email_only -- return a list of email addresses.
                       if not present, return a list of account profiles
                       (dicts).
        @disabled_only -- return disabled accounts.
        """
        domain = str(domain).lower()

        form = web.input(_unicode=True)
        email_only = ('email_only' in form)
        disabled_only = ('disabled_only' in form)

        qr = sql_lib_alias.get_basic_alias_profiles(domain=domain,
                                                    email_only=email_only,
                                                    disabled_only=disabled_only,
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
