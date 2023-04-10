import time
import re
from datetime import tzinfo, timedelta, datetime

from libs.l10n import TIMEZONE_OFFSETS
import settings

__timezone__ = None
__local_timezone__ = None
__timezones__ = {}

DEFAULT_DATETIME_INPUT_FORMATS = (
    "%Y-%m-%d %H:%M:%S",  # '2006-10-25 14:30:59'
    "%Y-%m-%d %H:%M",  # '2006-10-25 14:30'
    "%Y-%m-%d",  # '2006-10-25'
    "%Y/%m/%d %H:%M:%S",  # '2006/10/25 14:30:59'
    "%Y/%m/%d %H:%M",  # '2006/10/25 14:30'
    "%Y/%m/%d ",  # '2006/10/25 '
    "%m/%d/%Y %H:%M:%S",  # '10/25/2006 14:30:59'
    "%m/%d/%Y %H:%M",  # '10/25/2006 14:30'
    "%m/%d/%Y",  # '10/25/2006'
    "%m/%d/%y %H:%M:%S",  # '10/25/06 14:30:59'
    "%m/%d/%y %H:%M",  # '10/25/06 14:30'
    "%m/%d/%y",  # '10/25/06'
    "%H:%M:%S",  # '14:30:59'
    "%H:%M",  # '14:30'
)

ZERO = timedelta(0)


class UTCTimeZone(tzinfo):
    """UTC"""

    def utcoffset(self, dt):
        return ZERO

    def tzname(self, dt):
        return "UTC"

    def dst(self, dt):
        return ZERO

    def __repr__(self):
        return "<tzinfo UTC>"


UTC = UTCTimeZone()


class FixedOffset(tzinfo):
    """Fixed offset in minutes east from UTC."""

    def __init__(self, offset, name):
        self.__offset = timedelta(minutes=offset)
        self.__name = name

    def utcoffset(self, dt):
        return self.__offset

    def tzname(self, dt):
        return self.__name

    def dst(self, dt):
        return ZERO


for (tzname, offset) in list(TIMEZONE_OFFSETS.items()):
    __timezones__[tzname] = FixedOffset(offset, tzname)

re_timezone = re.compile(r"GMT\s?([+-]?)(\d+):(\d\d)", re.IGNORECASE)


def fix_gmt_timezone(tz):
    if isinstance(tz, str):
        b = re_timezone.match(tz)
        if b:
            sign = b.group(1)
            if not sign:
                sign = "+"

            hour = b.group(2)
            if hour in ["0", "00"]:
                return "UTC"

            minute = b.group(3)
            return "GMT" + sign + hour + ":" + minute
    return tz


def set_local_timezone(tz):
    global __local_timezone__
    __local_timezone__ = timezone(tz)


def get_local_timezone():
    return __local_timezone__


def timezone(tzname):
    # Validate tzname and return it
    if not tzname:
        return None

    if isinstance(tzname, str):
        # not pytz module imported, so just return None
        tzname = fix_gmt_timezone(tzname)
        tz = __timezones__.get(tzname, None)
        if not tz:
            tz = UTC
        return tz
    elif isinstance(tzname, tzinfo):
        return tzname
    else:
        return UTC


def pick_timezone(*args):
    for x in args:
        tz = timezone(x)
        if tz:
            return tz


def to_timezone(dt, tzinfo=None):
    """
    Convert a datetime to timezone
    """
    if not dt:
        return dt
    tz = pick_timezone(tzinfo, __timezone__)
    if not tz:
        return dt
    dttz = getattr(dt, "tzinfo", None)
    if not dttz:
        return dt.replace(tzinfo=tz)
    else:
        return dt.astimezone(tz)


def to_datetime_with_tzinfo(dt, tzinfo=None, formatstr=None):
    """
    Convert a date or time to datetime with tzinfo
    """
    if not dt:
        return dt

    tz = pick_timezone(tzinfo, __timezone__)

    if isinstance(dt, str):
        if not formatstr:
            formats = DEFAULT_DATETIME_INPUT_FORMATS
        else:
            formats = list(formatstr)
        d = None
        for fmt in formats:
            try:
                d = datetime(*time.strptime(dt, fmt)[:6])
            except ValueError:
                continue
        if not d:
            return None
        d = d.replace(tzinfo=tz)
    else:
        d = datetime(
            getattr(dt, "year", 1970),
            getattr(dt, "month", 1),
            getattr(dt, "day", 1),
            getattr(dt, "hour", 0),
            getattr(dt, "minute", 0),
            getattr(dt, "second", 0),
            getattr(dt, "microsecond", 0),
        )

        if not getattr(dt, "tzinfo", None):
            d = d.replace(tzinfo=tz)
        else:
            d = d.replace(tzinfo=dt.tzinfo)
    return to_timezone(d, tzinfo)


def utc_to_timezone(dt, timezone=None, format="%Y-%m-%d %H:%M:%S"):
    if not timezone:
        timezone = settings.LOCAL_TIMEZONE

    # Convert original timestamp to new timestamp with UTC timezone.
    t = to_datetime_with_tzinfo(dt, tzinfo=UTC)

    # Convert original timestamp (with UTC timezone) to timestamp with
    # local timezone.
    ft = to_datetime_with_tzinfo(t, tzinfo=timezone)

    if ft:
        # Check 'daylight saving time'
        if time.localtime().tm_isdst:
            ft += timedelta(seconds=3600)

        return ft.strftime(format)
    else:
        return "--"
