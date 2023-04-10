# Author: Zhang Huangbin <zhb@iredmail.org>

import web
from libs import iredutils
from libs.logger import logger
from controllers.utils import api_render
import settings

session = web.config.get("_session")


def require_login(func):
    def proxyfunc(*args, **kw):
        if session.get("logged"):
            return func(*args, **kw)
        else:
            session.kill()
            raise web.seeother("/login?msg=LOGIN_REQUIRED")

    return proxyfunc


def require_admin_login(func):
    def proxyfunc(*args, **kw):
        if session.get("logged"):
            if session.get("is_global_admin") or session.get("is_normal_admin"):
                return func(*args, **kw)
            else:
                if session.get("account_is_mail_user"):
                    raise web.seeother("/preferences?msg=PERMISSION_DENIED")
                else:
                    raise web.seeother("/domains?msg=PERMISSION_DENIED")
        else:
            session.kill()
            raise web.seeother("/login?msg=LOGIN_REQUIRED")

    return proxyfunc


def api_require_admin_login(func):
    def proxyfunc(*args, **kw):
        if session.get("logged"):
            if session.get("is_global_admin") or session.get("is_normal_admin"):
                return func(*args, **kw)
            else:
                session.kill()
                return api_render((False, "LOGIN_REQUIRED"))
        else:
            session.kill()
            return api_render((False, "LOGIN_REQUIRED"))

    return proxyfunc


def require_global_admin(func):
    def proxyfunc(*args, **kw):
        if session.get("is_global_admin"):
            return func(*args, **kw)
        else:
            if session.get("logged"):
                if session.get("account_is_mail_user"):
                    raise web.seeother("/preferences?msg=PERMISSION_DENIED")
                else:
                    raise web.seeother("/domains?msg=PERMISSION_DENIED")
            else:
                raise web.seeother("/login?msg=LOGIN_REQUIRED")

    return proxyfunc


def api_require_global_admin(func):
    if not iredutils.is_allowed_api_client(web.ctx.ip):
        return api_render((False, "NOT_AUTHORIZED"))

    def proxyfunc(*args, **kw):
        if session.get("is_global_admin"):
            return func(*args, **kw)
        else:
            if session.get("username"):
                return api_render((False, "PERMISSION_DENIED"))
            else:
                return api_render((False, "LOGIN_REQUIRED"))

    return proxyfunc


def require_user_login(func):
    def proxyfunc(*args, **kw):
        if session.get("account_is_mail_user"):
            return func(*args, **kw)
        else:
            session.kill()
            raise web.seeother("/login?msg=LOGIN_REQUIRED")

    return proxyfunc


def csrf_protected(f):
    def decorated(*args, **kw):
        form = web.input()

        if "csrf_token" not in form:
            return web.render("error_csrf.html")

        if not session.get("csrf_token"):
            session["csrf_token"] = iredutils.generate_random_strings(32)

        if form["csrf_token"] != session["csrf_token"]:
            return web.render("error_csrf.html")

        return f(*args, **kw)

    return decorated


# Used in user self-service
def require_preference_access(preference):
    def proxyfunc1(func):
        def proxyfunc2(*args, **kw):
            return func(*args, **kw)

        return proxyfunc2

    if session.get("is_global_admin") or session.get("is_normal_admin"):
        return proxyfunc1
    else:
        # session.get('account_is_mail_user')
        if preference in session.get("disabled_user_preferences", []):
            raise web.seeother("/preferences?msg=PERMISSION_DENIED")
        else:
            return proxyfunc1


def require_permission_create_domain(func):
    def proxyfunc(*args, **kw):
        if session.get("is_global_admin") or session.get("create_new_domains"):
            return func(*args, **kw)
        else:
            if session.get("account_is_mail_user"):
                raise web.seeother("/preferences?msg=PERMISSION_DENIED")
            else:
                raise web.seeother("/domains?msg=PERMISSION_DENIED")

    return proxyfunc


def require_permission_in_session(perm, present=False, not_present=False, value=""):
    def proxyfunc(func):
        def proxyargs(*args, **kwargs):
            if present:
                if perm in session:
                    return func(*args, **kwargs)

            if not_present:
                if perm not in session:
                    return func(*args, **kwargs)

            if value:
                if session.get(perm) == value:
                    return func(*args, **kwargs)

            if settings.LOG_PERMISSION_DENIED:
                logger.error("PERMISSION_DENIED raised in decorator "
                             "@require_permission_in_session: module=%s.py, "
                             "function=%s(), "
                             "permission=%s" % (func.__module__, func.__name__, perm))

            if session.get("account_is_mail_user"):
                raise web.seeother("/preferences?msg=PERMISSION_DENIED")
            else:
                raise web.seeother("/domains?msg=PERMISSION_DENIED")

        return proxyargs

    return proxyfunc
