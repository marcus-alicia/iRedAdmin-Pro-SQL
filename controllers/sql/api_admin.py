import web

from controllers.utils import api_render

from libs.sqllib import SQLWrap
from libs.sqllib import decorators, api_utils
from libs.sqllib import admin as sql_lib_admin
from libs.sqllib import general as sql_lib_general

import settings


# Parameter names used in API interface and web form, both POST and PUT.
_param_maps = [('maxDomains', 'create_max_domains'),
               ('maxUsers', 'create_max_users'),
               ('maxAliases', 'create_max_aliases'),
               ('maxLists', 'create_max_lists'),
               ('maxQuota', 'create_max_quota'),
               ('quotaUnit', 'create_quota_unit')]


class APIAdmin:
    @decorators.api_require_global_admin
    def GET(self, mail):
        """Get profile of a standalone domain admin.

        curl -X GET -i -b cookie.txt https://<server>/api/admin/<mail>
        """
        mail = str(mail).lower()

        _wrap = SQLWrap()
        conn = _wrap.conn

        qr = sql_lib_admin.get_profile(mail=mail, conn=conn)
        if qr[0]:
            profile = api_utils.export_sql_record(record=qr[1],
                                                  remove_columns=settings.API_HIDDEN_ADMIN_PROFILES)

            profile['isglobaladmin'] = 0
            if sql_lib_general.is_global_admin(admin=mail, conn=conn):
                profile['isglobaladmin'] = 1

            _qr = sql_lib_admin.get_managed_domains(admin=mail,
                                                    domain_name_only=True,
                                                    listed_only=True,
                                                    conn=conn)
            if _qr[0]:
                profile['managed_domains'] = _qr[1]

            return api_render((True, profile))
        else:
            return api_render(qr)

    @decorators.api_require_global_admin
    def POST(self, mail):
        """Create a new domain.

        curl -X POST -i -b cookie.txt -d "var=<value>&var2=value2" https://<server>/api/admin/<mail>

        :param mail: admin email address.

        Form parameters:

        `name`: the display name of this admin
        `password`: admin's password
        `accountStatus`: account status (active, disabled)
        `domainGlobalAdmin`: Mark this admin as global admin (yes, no).
        `language`: default preferred language for new user.
                         e.g. en_US for English, de_DE for Deutsch.

        Form parameters listed below are used by normal domain admin, so they
        cannot be set while `domainGlobalAdmin=yes`.

        `maxDomains`: how many mail domains this admin can create.
        `maxQuota`: how much mailbox quota this admin can create.
                    Quota is shared by all domains created/managed by this
                    admin. Sample: 10, 20, 30. Must be used with @quotaUnit.
        `quotaUnit`: quota unit of @maxQuota. Must be used with @maxQuota.
        `maxUsers`: how many mail users this admin can create.
                    It's shared by all domains created/managed by this admin.
        `maxAliases`: how many mail aliases this admin can create.
                      It's shared by all domains created/managed by this admin.
        `maxUsers`: how many mailing lists this admin can create.
                    It's shared by all domains created/managed by this admin.
        """
        form = web.input()

        form['mail'] = mail
        form['cn'] = form.get('name')
        form['newpw'] = form.get('password')
        form['confirmpw'] = form.get('password')
        form['domainGlobalAdmin'] = form.get('isGlobalAdmin')
        form['preferredLanguage'] = form.get('language')

        for (k_api, k_web) in _param_maps:
            if k_api in form:
                form[k_web] = form[k_api]

        # [(api_form_name, web_form_name), ...]
        for (k_api, k_web) in [('disableViewingMailLog', 'disable_viewing_mail_log'),
                               ('disableManagingQuarantinedMails', 'disable_managing_quarantined_mails')]:
            v = form.get(k_api, '')
            if v == 'yes':
                form[k_web] = 'yes'

        qr = sql_lib_admin.add_admin_from_form(form=form)
        return api_render(qr)

    @decorators.api_require_global_admin
    def DELETE(self, mail):
        """Delete an existing mail domain.

        curl -X DELETE -i -b cookie.txt https://<server>/api/admin/<mail>
        """
        qr = sql_lib_admin.delete_admins(mails=[mail], revoke_admin_privilege_from_user=False)
        return api_render(qr)

    @decorators.api_require_global_admin
    def PUT(self, mail):
        """Update profile of existing standalone domain admin.

        curl -X PUT -i -b cookie.txt -d "var=<value>" https://<server>/api/domain/<domain>
        curl -X PUT -i -b cookie.txt -d "var=<value>&var2=<value2>" https://<server>/api/domain/<domain>

        :param mail: full admin email address.

        Form parameters:

        `name`: the display name of this admin
        `password`: admin's password
        `accountStatus`: account status (active, disabled)
        `domainGlobalAdmin`: Mark this admin as global admin (yes, no).
        `language`: default preferred language for new user.
                    e.g. en_US for English, de_DE for Deutsch.

        Form parameters listed below are used by normal domain admin, so they
        cannot be set while `domainGlobalAdmin=yes`.

        `maxDomains`: how many mail domains this admin can create.
        `maxQuota`: how much mailbox quota this admin can create.
                         Quota is shared by all domains created/managed by this
                         admin. Sample: 10, 20, 30. Must be used with @quotaUnit.
        `quotaUnit`: quota unit of @maxQuota. Must be used with @maxQuota.
        `maxUsers`: how many mail users this admin can create.
                         It's shared by all domains created/managed by this admin.
        `maxAliases`: how many mail aliases this admin can create.
                           It's shared by all domains created/managed by this admin.
        `maxUsers`: how many mailing lists this admin can create.
                         It's shared by all domains created/managed by this admin.
        """
        form = web.input()

        for (k_api, k_web) in _param_maps:
            if k_api in form:
                form[k_web] = form[k_api]

        qr = sql_lib_admin.api_update_profile(form=form, mail=mail)
        return api_render(qr)
