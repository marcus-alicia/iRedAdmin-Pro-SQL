import web

from controllers.utils import api_render
from libs import iredpwd

from libs.sqllib import decorators
from libs.sqllib import user as sql_lib_user
from libs.sqllib import admin as sql_lib_admin


class APIVerifyPassword:
    @decorators.api_require_global_admin
    def POST(self, account_type, mail):
        """Verify submitted (plain) password against the one stored in SQL db.

        curl -X POST -i -b cookie.txt -d "var=<value>" https://<server>/api/verify_password/user/<mail>
        curl -X POST -i -b cookie.txt -d "var=<value>" https://<server>/api/verify_password/admin/<mail>

        Required parameters:

        @password - plain password you want to verify
        """
        mail = str(mail).lower()

        form = web.input()
        pw = form.get('password', '')

        if not pw:
            return api_render((False, 'EMPTY_PASSSWORD'))

        try:
            if account_type == 'admin':
                qr = sql_lib_admin.get_profile(mail=mail, columns=['password'], conn=None)
            else:
                qr = sql_lib_user.simple_profile(mail=mail, columns=['password'])

            if qr[0]:
                pw_in_db = str(qr[1].password)
                qr_pw = iredpwd.verify_password_hash(pw_in_db, pw)

                return api_render(qr_pw)
            else:
                return api_render(qr)
        except Exception as e:
            return api_render((False, repr(e)))
