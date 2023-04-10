import sys
import logging
import traceback
from logging.handlers import SysLogHandler

import web
from libs import iredutils
import settings

session = web.config.get("_session")

# Set application name.
logger = logging.getLogger("iredadmin")

# Set log level.
_log_level = getattr(logging, str(settings.LOG_LEVEL).upper())
logger.setLevel(_log_level)

if settings.LOG_TARGET == "stdout":
    _handler = logging.StreamHandler()
    _formatter = logging.Formatter("%(message)s (%(pathname)s, L%(lineno)d)")
else:
    # Defaults to "syslog":
    _facility = getattr(SysLogHandler, "LOG_" + settings.SYSLOG_FACILITY.upper())
    _formatter = logging.Formatter("%(name)s %(message)s (%(pathname)s, L%(lineno)d)")

    if settings.SYSLOG_SERVER.startswith("/"):
        # Log to a local socket
        _handler = SysLogHandler(address=settings.SYSLOG_SERVER, facility=_facility)
    else:
        # Log to a network address
        _server = (settings.SYSLOG_SERVER, settings.SYSLOG_PORT)
        _handler = SysLogHandler(address=_server, facility=_facility)

_handler.setFormatter(_formatter)
logger.addHandler(_handler)


def log_traceback():
    exc_type, exc_value, exc_traceback = sys.exc_info()
    msg = traceback.format_exception(exc_type, exc_value, exc_traceback)
    logger.error(msg)


def log_activity(msg, admin="", domain="", username="", event="", loglevel="info"):
    try:
        if not admin:
            admin = session.get("username")

        if username and not domain:
            domain = username.split("@", 1)[-1]

        msg = str(msg)

        # Prepend '[API]' in log message
        try:
            if web.ctx.fullpath.startswith("/api/"):
                msg = "[API] " + msg
        except:
            pass

        web.conn_iredadmin.insert(
            "log",
            admin=str(admin),
            domain=str(domain),
            username=str(username),
            loglevel=str(loglevel),
            event=str(event),
            msg=msg,
            ip=web.ctx.ip,
            timestamp=iredutils.get_gmttime(),
        )

        if loglevel == "info":
            logger.info("{0} admin={1}, domain={2}, username={3}, event={4}, "
                        "ip={5}".format(msg, admin, domain, username, event, web.ctx.ip))
        elif loglevel == "error":
            logger.error("{0} admin={1}, domain={2}, username={3}, event={4}, "
                         "ip={5}".format(msg, admin, domain, username, event, web.ctx.ip))
    except:
        pass

    return None
