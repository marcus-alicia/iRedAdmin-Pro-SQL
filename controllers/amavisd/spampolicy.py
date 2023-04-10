# Author: Zhang Huangbin <zhb@iredmail.org>

import web
import settings
from libs import iredutils
from controllers import decorators
from libs.amavisd import spampolicy as spampolicylib

# API
from controllers.utils import api_render

if settings.backend == 'ldap':
    from libs.ldaplib.general import is_domain_admin
else:
    from libs.sqllib.general import is_domain_admin


session = web.config.get('_session')


def _check_privilege(admin, account_type, account):
    """Check whether current admin has privilege to update account spam policy.

    Return (True, {'account': xx, 'account_type': xx}) if has required privilege.
    Return (False, <reason>) if no required privilege.
    """
    if account_type == 'global':
        account = '@.'

        # Check privilege
        if not session.get('is_global_admin'):
            return False, 'PERMISSION_DENIED'
    elif account_type == 'domain':
        domain = account
        account = '@' + domain
    elif account_type == 'user':
        domain = account.split('@', 1)[-1]
    else:
        return False, 'INVALID_ACCOUNT'

    if account_type in ['domain', 'user']:
        # Check whether it's managed by admin
        if not is_domain_admin(domain=domain, admin=admin):
            return False, 'PERMISSION_DENIED'

    return True, {'account': account, 'account_type': account_type}


class SpamPolicy:
    def _get_account_and_type(self):
        # account, type:
        #   - @.:               global
        #   - domain.com:       domain
        #   - user@domain.com:  user, user_preference
        current_url = web.ctx.environ['PATH_INFO']
        if current_url == '/system/spampolicy':
            # Global policy
            account = '@.'
            account_type = 'global'
        elif current_url.startswith('/profile/domain'):
            # Per-domain policy
            account = '@' + current_url.split('/')[-1]
            account_type = 'domain'
        elif current_url.startswith('/profile/user'):
            # per-user policy, modifying by admin.
            account = current_url.split('/')[-1]
            account_type = 'user'
        else:
            # per-user preferences
            # web.ctx.PATH_INFO == '/preferences/spampolicy'
            account = session['username']
            account_type = 'user_preference'

        return {'account': account,
                'account_type': account_type,
                'url': current_url}

    @decorators.require_preference_access('spampolicy')
    @decorators.require_login
    def GET(self, account=None):
        d = self._get_account_and_type()
        account = d['account']
        account_type = d['account_type']
        current_url = d['url']

        if account_type == 'global':
            # Check privilege
            if not session.get('is_global_admin'):
                raise web.seeother('/domains?msg=PERMISSION_DENIED')
        elif account_type in ['domain', 'user']:
            domain = account.split('@', 1)[-1]

            # Check whether it's managed by admin
            if not is_domain_admin(domain=domain, admin=session.get('username')):
                raise web.seeother('/domains?msg=PERMISSION_DENIED')

        (success, policy) = spampolicylib.get_spam_policy(account=account)
        if not success:
            if account_type == 'user_preference':
                raise web.seeother('/preferences?msg=%s' % web.urlquote(policy))
            else:
                raise web.seeother('/domains?msg=%s' % web.urlquote(policy))

        global_spam_score = spampolicylib.get_global_spam_score()

        return web.render(
            'amavisd/spampolicy.html',
            account_type=account_type,
            spampolicy=policy,
            global_spam_score=global_spam_score,
            custom_ban_rules=settings.AMAVISD_BAN_RULES,
            current_url=current_url,
            msg=web.input().get('msg'),
        )

    @decorators.require_preference_access('spampolicy')
    @decorators.require_login
    def POST(self, account=None):
        if account:
            if iredutils.is_domain(account):
                policy_account = '@' + account
                current_url = '/profile/domain/spampolicy/' + account
            elif iredutils.is_email(account):
                policy_account = str(account)
                current_url = '/profile/user/spampolicy/' + policy_account
        else:
            d = self._get_account_and_type()
            policy_account = d['account']
            current_url = d['url']

        form = web.input(banned_rulenames=[])

        qr = spampolicylib.update_spam_policy(account=policy_account, form=form)
        if qr[0]:
            raise web.seeother(current_url + '?msg=UPDATED')
        else:
            raise web.seeother(current_url + '?msg=%s' % web.urlquote(qr[1]))


class APISpamPolicy:
    @decorators.require_preference_access('spampolicy')
    @decorators.require_login
    def GET(self, account_type, account=None):
        qr = _check_privilege(admin=session.get('username'),
                              account_type=account_type,
                              account=account)
        if not qr[0]:
            return api_render(qr)

        account = qr[1]['account']

        qr = spampolicylib.get_spam_policy(account=account)
        return api_render(qr)

    @decorators.require_preference_access('spampolicy')
    @decorators.require_login
    def PUT(self, account_type, account=None):
        qr = _check_privilege(admin=session.get('username'),
                              account_type=account_type,
                              account=account)
        if not qr[0]:
            return api_render(qr)

        form = web.input(_unicode=False)

        account = qr[1]['account']
        qr = spampolicylib.api_update_spam_policy(account=account, form=form)
        return api_render(qr)

    @decorators.require_preference_access('spampolicy')
    @decorators.require_login
    def DELETE(self, account_type, account=None):
        qr = _check_privilege(admin=session.get('username'),
                              account_type=account_type,
                              account=account)
        if not qr[0]:
            return api_render(qr)

        account = qr[1]['account']

        qr = spampolicylib.delete_spam_policy(account=account)
        return api_render(qr)
