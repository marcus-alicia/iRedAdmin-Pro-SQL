# Author: Zhang Huangbin <zhb@iredmail.org>

import os

import web
from jinja2 import Environment, FileSystemLoader

# Directory to be used as the Python egg cache directory.
# Note that the directory specified must exist and be writable by the
# user that the daemon process run as.
os.environ["PYTHON_EGG_CACHE"] = "/tmp/.iredadmin-eggs"
os.environ["LC_ALL"] = "C"

# Absolute path to this file.
rootdir = os.path.abspath(os.path.dirname(__file__))

import settings
from . import iredutils
from . import iredpwd
from . import jinja_filters
from . import ireddate
from . import hooks

# Set debug mode.
web.config.debug = settings.DEBUG

# Set session parameters.
web.config.session_parameters["cookie_name"] = "iRedAdmin-Pro-%s" % settings.backend.upper()
web.config.session_parameters["cookie_domain"] = None
web.config.session_parameters["ignore_expiry"] = True
web.config.session_parameters["ignore_change_ip"] = settings.SESSION_IGNORE_CHANGE_IP
web.config.session_parameters["timeout"] = settings.SESSION_TIMEOUT
web.config.session_parameters["httponly"] = True
web.config.session_parameters["samesite"] = "Strict"
# web.config.session_parameters['secure'] = True

# Initialize session object.
__sql_dbn = "mysql"
if settings.backend == "pgsql":
    __sql_dbn = "postgres"

conn_iredadmin = iredutils.get_db_conn(db_name="iredadmin", sql_dbn=__sql_dbn)
web.conn_iredadmin = conn_iredadmin

# URL handlers.
# Import backend related urls.
urls_backend = []
if settings.backend == "ldap":
    from controllers.ldap.urls import urls as urls_backend
elif settings.backend in ["mysql", "pgsql"]:
    from controllers.sql.urls import urls as urls_backend

urls = urls_backend

# Amavisd.
if (
    settings.amavisd_enable_quarantine
    or settings.amavisd_enable_logging
    or settings.amavisd_enable_policy_lookup
):
    from controllers.amavisd.urls import urls as urls_amavisd
    urls += urls_amavisd

    web.conn_amavisd = iredutils.get_db_conn(db_name="amavisd", sql_dbn=__sql_dbn)
else:
    web.conn_amavisd = None

# iRedAPD
from controllers.iredapd.urls import urls as urls_iredapd
urls += urls_iredapd
if settings.iredapd_enabled:
    web.conn_iredapd = iredutils.get_db_conn(db_name="iredapd", sql_dbn=__sql_dbn)
else:
    web.conn_iredapd = None

# iRedAdmin.
from controllers.panel.urls import urls as urls_panel
urls += urls_panel

# mlmmj.
from controllers.mlmmj.urls import urls as urls_mlmmj
urls += urls_mlmmj

# Fail2ban.
if settings.fail2ban_enabled:
    from controllers.f2b.urls import urls as urls_f2b
    urls += urls_f2b
    web.conn_f2b = iredutils.get_db_conn(db_name="fail2ban", sql_dbn=__sql_dbn)
else:
    web.conn_f2b = None

# Initialize application object.
app = web.application(urls)

session_initializer = {
    "webmaster": settings.webmaster,
    "username": None,
    "logged": False,
    # Admin
    "is_global_admin": False,
    "is_normal_admin": False,
    # normal mail user
    "account_is_mail_user": False,
    "failed_times": 0,  # Integer.
    "lang": settings.default_language,
    # Show used quota.
    "show_used_quota": settings.SHOW_USED_QUOTA,
    # Amavisd related features.
    "amavisd_enable_quarantine": settings.amavisd_enable_quarantine,
    "amavisd_enable_logging": settings.amavisd_enable_logging,
    "amavisd_enable_policy_lookup": settings.amavisd_enable_policy_lookup,
    # iRedAPD related features.
    "iredapd_enabled": settings.iredapd_enabled,
    "fail2ban_enabled": settings.fail2ban_enabled,
}

session = web.session.Session(
    app=app,
    store=web.session.DBStore(conn_iredadmin, "sessions"),
    initializer=session_initializer,
)

web.config._session = session


# Generate CSRF token and store it in session.
def csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = iredutils.generate_random_strings(32)

    return session["csrf_token"]


jinja_env_vars = {
    # Set global variables for Jinja2 template
    "_": iredutils.ired_gettext,  # Override _() which provided by Jinja2.
    "ctx": web.ctx,  # Used to get 'homepath'.
    "skin": settings.SKIN,
    "session": web.config._session,
    "backend": settings.backend,
    "csrf_token": csrf_token,
    "page_size_limit": settings.PAGE_SIZE_LIMIT,
    "url_support": settings.URL_SUPPORT,
    # newsletter (mlmmj mailing list)
    "newsletter_base_url": settings.NEWSLETTER_BASE_URL,
    # Brand logo, name, description
    "brand_logo": settings.BRAND_LOGO,
    "brand_name": settings.BRAND_NAME,
    "brand_desc": settings.BRAND_DESC,
    "brand_favicon": settings.BRAND_FAVICON,
}

jinja_env_filters = {
    "file_size_format": jinja_filters.file_size_format,
    "cut_string": jinja_filters.cut_string,
    "convert_to_percentage": jinja_filters.convert_to_percentage,
    "epoch_seconds_to_gmt": iredutils.epoch_seconds_to_gmt,
    "epoch_days_to_date": iredutils.epoch_days_to_date,
    "set_datetime_format": iredutils.set_datetime_format,
    "generate_random_password": iredpwd.generate_random_password,
    "utc_to_timezone": ireddate.utc_to_timezone,
}

_default_template_dir = rootdir + "/../templates/" + settings.SKIN


# Define template renders.
def render_template(template_name, **kwargs):
    jinja_env = Environment(
        loader=FileSystemLoader(_default_template_dir),
        extensions=["jinja2.ext.do"],
    )

    jinja_env.globals.update(jinja_env_vars)
    jinja_env.filters.update(jinja_env_filters)

    web.header("Content-Type", "text/html")
    return jinja_env.get_template(template_name).render(kwargs)


class SessionExpired(web.HTTPError):
    def __init__(self, message):
        try:
            # Expire the cookie. Fixed in webpy master branch on Sep 21, 2020.
            cookie_name = web.config.session_parameters['cookie_name']
            web.setcookie(cookie_name, session.session_id, expires=-1)
            session.kill()
        except:
            pass

        message = web.seeother("/login?msg=SESSION_EXPIRED")
        web.HTTPError.__init__(self, "303 See Other", {}, data=message)


# Load hooks
app.add_processor(web.loadhook(hooks.hook_set_language))

if settings.DEBUG:
    app.internalerror = web.debugerror
elif settings.MAIL_ERROR_TO_WEBMASTER:
    # Mail 500 error to webmaster.
    app.internalerror = web.emailerrors(settings.webmaster, web.webapi._InternalError)

# Store objects in 'web' module.
web.render = render_template
web.session.SessionExpired = SessionExpired
