# Author: Zhang Huangbin <zhb@iredmail.org>

import web
import settings
from controllers import decorators

from libs import iredutils
from libs.panel.domain_ownership import get_pending_domains, verify_domain_ownership

if settings.backend == 'ldap':
    from libs.ldaplib.domain import update_ownership_verified_domain
    from libs.ldaplib.domain import enable_domain_without_ownership_verification
else:
    from libs.sqllib.domain import update_ownership_verified_domain
    from libs.sqllib.domain import enable_domain_without_ownership_verification

session = web.config.get('_session', {})


class VerifyOwnership:
    @decorators.require_admin_login
    def GET(self):
        qr = get_pending_domains()
        if qr[0]:
            ownership_verify_codes = qr[1]
        else:
            raise web.seeother('/domains?msg=%s' % web.urlquote(qr[1]))

        return web.render('panel/domain_ownership.html',
                          ownership_verify_codes=ownership_verify_codes,
                          msg=web.input().get('msg', ''))

    @decorators.require_admin_login
    def POST(self):
        form = web.input(domain=[])

        if 'verify' in form:
            action = 'verify'
        elif 'enable_without_verification' in form:
            action = 'enable_without_verification'
        else:
            raise web.seeother('/verify/domain_ownership?msg=INVALID_ACTION')

        domains = form.get('domain', [])
        domains = [str(d).lower() for d in domains if iredutils.is_domain(d)]

        if action == 'verify':
            _qr = verify_domain_ownership(domains=domains)
            if _qr[0]:
                verified_domains = _qr[1]
                for (pd, ad) in verified_domains:
                    qr = update_ownership_verified_domain(primary_domain=pd,
                                                          alias_domain=ad)
                    if not qr[0]:
                        raise web.seeother('/verify/domain_ownership?msg=%s' % web.urlquote(qr[1]))

                raise web.seeother('/verify/domain_ownership')
            else:
                raise web.seeother('/verify/domain_ownership?msg=%s' % web.urlquote(_qr[1]))
        elif action == 'enable_without_verification':
            # Enable domains, and mark them as verified
            if not session.get('is_global_admin'):
                raise web.seeother('/verify/domain_ownership?msg=PERMISSION_DENIED')

            qr = enable_domain_without_ownership_verification(domains=domains)
            if not qr[0]:
                raise web.seeother('/verify/domain_ownership?msg=%s' % web.urlquote(qr[1]))

            raise web.seeother('/verify/domain_ownership')
