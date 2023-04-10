# Author: Zhang Huangbin <zhb@iredmail.org>

import web

import settings
from controllers import decorators as base_decorators
from controllers.utils import api_render
from libs import iredutils
from libs.logger import logger
from libs.sqllib import general as sql_lib_general

session = web.config.get('_session', {})

# require_api_auth_token = base_decorators.require_api_auth_token
require_login = base_decorators.require_login
require_admin_login = base_decorators.require_admin_login
require_global_admin = base_decorators.require_global_admin
csrf_protected = base_decorators.csrf_protected
require_permission_create_domain = base_decorators.require_permission_create_domain
require_preference_access = base_decorators.require_preference_access

api_require_admin_login = base_decorators.api_require_admin_login
api_require_global_admin = base_decorators.api_require_global_admin


def require_domain_access(func):
    def proxyfunc(*args, **kw):
        if not session.get('username'):
            raise web.seeother('/login?msg=LOGIN_REQUIRED')

        # Check domain global admin.
        if session.get('is_global_admin'):
            return func(*args, **kw)
        else:
            username = session.get('username')
            # admin/user is viewing its own data
            if username == kw.get('mail') \
               or username.endswith('@' + kw.get('domain', 'NONE')):
                return func(*args, **kw)

            if 'domain' in kw and iredutils.is_domain(kw.get('domain')):
                domain = web.safestr(kw['domain'])
            elif 'mail' in kw and iredutils.is_email(kw.get('mail')):
                domain = web.safestr(kw['mail']).split('@')[-1]
            elif 'admin' in kw and iredutils.is_email(kw.get('admin')):
                domain = web.safestr(kw['admin']).split('@')[-1]
            else:
                domain = None
                # Try to use the first valid domain name or email address as
                # key, it's passed from controllers/*.
                for arg in args:
                    if iredutils.is_domain(arg):
                        domain = arg
                        break
                    elif iredutils.is_email(arg):
                        domain = arg.split('@', 1)[-1]
                        break

                if not domain:
                    if settings.LOG_PERMISSION_DENIED:
                        logger.error("PERMISSION_DENIED (1) raised in "
                                     "@require_domain_access, triggered in module: "
                                     "%s.py, function: %s(). No target domain for "
                                     "accessing." % (func.__module__, func.__name__))

                    raise web.seeother('/domains?msg=PERMISSION_DENIED')

            # Check whether is domain admin.
            is_admin = sql_lib_general.is_domain_admin(domain=domain,
                                                       admin=username)
            if is_admin:
                return func(*args, **kw)
            else:
                if settings.LOG_PERMISSION_DENIED:
                    logger.error("PERMISSION_DENIED (2) raised in "
                                 "@require_domain_access, triggered in module: %s.py, "
                                 "function: %s(), accessing data: admin=%s, "
                                 "domain=%s" % (func.__module__, func.__name__, username, domain))

                raise web.seeother('/domains?msg=PERMISSION_DENIED')
    return proxyfunc


def require_user_login(func):
    def proxyfunc(self, *args, **kw):
        if session.get('account_is_mail_user'):
            return func(self, *args, **kw)

        """
        elif session.get('is_normal_admin') and session.get('admin_is_mail_user'):
            # Admin manages other domains but not self domain.
            # <admin>@<domain.com> doesn't manage <domain.com>
            admin = session.get('username')
            domain = admin.split('@', 1)[-1]
            if not sql_lib_general.is_domain_admin(domain=domain, admin=admin):
                return func(self, *args, **kw)
        """

        session.kill()
        raise web.seeother('/login?msg=LOGIN_REQUIRED')
    return proxyfunc


# self-service.
def require_ml_owner_or_moderator(func):
    def proxyfunc(*args, **kw):
        username = session.get('username')
        if not username:
            raise web.seeother('/login?msg=LOGIN_REQUIRED')

        mail = None
        if 'mail' in kw:
            # the mailing list
            mail = kw['mail']
            if not iredutils.is_email(mail):
                raise web.seeother("/self-service/mls?msg=INVALID_MAILLIST")
        else:
            for i in args:
                if iredutils.is_email(i):
                    mail = i
                    break

        if not mail:
            raise web.seeother("/self-service/mls?msg=INVALID_MAILLIST")

        # Check whether user is an owner or moderator.
        _is_owner_or_moderator = sql_lib_general.is_ml_owner_or_moderator(ml=mail, user=username, conn=None)
        if _is_owner_or_moderator:
            return func(*args, **kw)
        else:
            if settings.LOG_PERMISSION_DENIED:
                logger.error("PERMISSION_DENIED (2) raised in "
                             "@require_ml_owner_or_moderator, triggered in module: %s.py, "
                             "function: %s(), accessing data: user=%s, "
                             "maillist=%s" % (func.__module__, func.__name__, username, mail))

            raise web.seeother('/self-service/mls?msg=PERMISSION_DENIED')

    return proxyfunc


def api_require_domain_access(func):
    def proxyfunc(*args, **kw):
        if not iredutils.is_allowed_api_client(web.ctx.ip):
            return api_render((False, 'NOT_AUTHORIZED'))

        if not session.get('username'):
            return api_render((False, 'LOGIN_REQUIRED'))

        # Check domain global admin.
        if session.get('is_global_admin'):
            return func(*args, **kw)
        else:
            username = session.get('username')
            # admin/user is viewing its own data
            if username == kw.get('mail') \
               or username.endswith('@' + kw.get('domain', 'NONE')):
                return func(*args, **kw)

            if 'domain' in kw and iredutils.is_domain(kw.get('domain')):
                domain = web.safestr(kw['domain'])
            elif 'mail' in kw and iredutils.is_email(kw.get('mail')):
                domain = web.safestr(kw['mail']).split('@')[-1]
            elif 'admin' in kw and iredutils.is_email(kw.get('admin')):
                domain = web.safestr(kw['admin']).split('@')[-1]
            else:
                domain = None
                # Try to use the first valid domain name or email address as
                # key, it's passed from controllers/*.
                for arg in args:
                    if iredutils.is_domain(arg):
                        domain = arg
                        break
                    elif iredutils.is_email(arg):
                        domain = arg.split('@', 1)[-1]
                        break

                if not domain:
                    if settings.LOG_PERMISSION_DENIED:
                        logger.error("PERMISSION_DENIED (1) raised in "
                                     "@require_domain_access: module=%s.py, "
                                     "function=%s(), admin=%s. "
                                     "No target domain for accessing." % (func.__module__, func.__name__, username))

                    return api_render((False, 'PERMISSION_DENIED'))

            # Check whether is domain admin.
            is_admin = sql_lib_general.is_domain_admin(domain=domain,
                                                       admin=username)
            if is_admin:
                return func(*args, **kw)
            else:
                if settings.LOG_PERMISSION_DENIED:
                    logger.error("PERMISSION_DENIED (2) raised in "
                                 "@require_domain_access: module=%s.py, "
                                 "function=%s(), "
                                 "admin=%s, "
                                 "domain=%s" % (func.__module__, func.__name__, username, domain))

                return api_render((False, 'PERMISSION_DENIED'))
    return proxyfunc
