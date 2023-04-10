# Author: Zhang Huangbin <zhb@iredmail.org>

import web
from libs.iredapd import greylist as iredapd_greylist
import settings

if settings.backend == 'ldap':
    from libs.ldaplib import decorators
else:
    from libs.sqllib import decorators


class DefaultGreylisting:
    @decorators.require_global_admin
    def GET(self):
        gl_setting = iredapd_greylist.get_greylist_setting(account='@.')
        gl_whitelists = iredapd_greylist.get_greylist_whitelists(account='@.')
        gl_whitelist_domains = iredapd_greylist.get_greylist_whitelist_domains()

        # Get greylisting tracking data
        (_status, _result) = iredapd_greylist.get_tracking_data(account='@.')
        if not _status:
            raise web.seeother('/domains?msg=%s' % web.urlquote(_result))
        else:
            tracking_records = _result

        return web.render('iredapd/greylisting_global.html',
                          gl_setting=gl_setting,
                          gl_whitelists=gl_whitelists,
                          gl_whitelist_domains=gl_whitelist_domains,
                          parent_setting={},
                          tracking_records=tracking_records,
                          msg=web.input().get('msg'))

    @decorators.require_global_admin
    def POST(self):
        form = web.input()
        qr = iredapd_greylist.update_greylist_settings_from_form(account='@.', form=form)

        if qr[0]:
            raise web.seeother('/system/greylisting?msg=GL_UPDATED')
        else:
            raise web.seeother('/system/greylisting?msg=%s' % web.urlquote(qr[1]))


class GreylistingRawTrackingData:
    @decorators.require_domain_access
    def GET(self, domain):
        (_status, _result) = iredapd_greylist.get_domain_tracking_data(domain=domain)
        if not _status:
            raise web.seeother('/domains?msg=%s' % web.urlquote(_result))

        return web.render('iredapd/greylisting_tracking_records.html',
                          domain=domain,
                          tracking_records=_result)
