# Author: Zhang Huangbin <zhb@iredmail.org>

import web

from controllers.utils import api_render
from libs.sqllib import decorators
from libs.sqllib import ml as sql_lib_ml
from libs.sqllib import api_utils

session = web.config.get('_session')


class APIMLS:
    @decorators.api_require_domain_access
    def GET(self, domain):
        """List all mailing lists in given domain.

        curl -X GET -i -b cookie.txt https://<server>/api/mls/<domain>

        Optional parameters:

        @email_only -- return a list of mailing list addresses.
                       if not present, return a list of mailing list profiles
                       (dicts).
        """
        domain = str(domain).lower()

        form = web.input(_unicode=True)
        email_only = ('email_only' in form)

        qr = sql_lib_ml.get_basic_ml_profiles(domain=domain,
                                              email_only=email_only,
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


class APIML:
    @decorators.api_require_domain_access
    def GET(self, mail):
        """Export mailing list profile.

        curl -X GET -i -b cookie.txt https://<server>/api/ml/<mail>

        Optional arguments:

        @with_subscribers -- if set to 'yes', all subscribers will be returned.
        """
        mail = str(mail).lower()

        form = web.input(_unicode=False)
        with_subscribers = ('with_subscribers' in form)

        qr = sql_lib_ml.get_profile(mail=mail,
                                    with_subscribers=with_subscribers,
                                    conn=None)

        if qr[0]:
            profile = api_utils.export_sql_record(record=qr[1])
            return api_render((True, profile))
        else:
            return api_render(qr)

    @decorators.api_require_domain_access
    def DELETE(self, mail):
        """Delete a mailing list.

        curl -X DELETE -i -b cookie.txt https://<server>/api/ml/<mail>
        """
        mail = str(mail).lower()
        form = web.input()

        keep_archive = True
        if form.get('keep_archive') == 'no':
            keep_archive = False

        qr = sql_lib_ml.delete_maillists(accounts=[mail],
                                         keep_archive=keep_archive,
                                         conn=None)
        return api_render(qr)

    @decorators.api_require_domain_access
    def POST(self, mail):
        """Create a new mail alias account.

        curl -X POST -i -b cookie.txt -d "..." https://<server>/api/ml/<email>

        Optional POST parameters:

        """
        mail = str(mail).lower()
        (listname, domain) = mail.split('@', 1)

        form = web.input()

        form['listname'] = listname
        form['domainName'] = domain

        qr = sql_lib_ml.add_ml_from_web_form(domain=domain, form=form, conn=None)
        return api_render(qr)

    @decorators.api_require_domain_access
    def PUT(self, mail):
        """Update mailing list profile.

        curl -X PUT -i -b cookie.txt -d "var=<value>" https://<server>/api/ml/<mail>
        curl -X PUT -i -b cookie.txt -d "var=<value>&var2=<value2>" https://<server>/ml/<mail>

        Optional PUT data:

        """
        mail = str(mail).lower()
        form = web.input()
        qr = sql_lib_ml.api_update_profile(mail=mail, form=form, conn=None)
        return api_render(qr)
