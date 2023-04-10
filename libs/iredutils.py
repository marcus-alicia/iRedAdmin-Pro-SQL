# Author: Zhang Huangbin <zhb@iredmail.org>

import datetime
import time
import re
import random
import subprocess
import smtplib
import os
import gettext
import inspect
import glob
import socket
import ipaddress
from typing import Union, List, Tuple, Set, Dict, Any

import simplejson as json
import web

import settings
from libs import regxes, l10n

# Priority used in SQL table `amavisd.mailaddr` and iRedAPD plugin `throttle`.
# 0 is the lowest priority.
# Reference: http://www.amavis.org/README.lookups.txt
#
# The following order (implemented by sorting on the 'priority' field
# in DESCending order, zero is low priority) is recommended, to follow
# the same specific-to-general principle as in other lookup tables;
#   9 - lookup for user+foo@sub.example.com
#   8 - lookup for user@sub.example.com (only if $recipient_delimiter is '+')
#   7 - lookup for user+foo (only if domain part is local)
#   6 - lookup for user     (only local; only if $recipient_delimiter is '+')
#   5 - lookup for @sub.example.com
#   3 - lookup for @.sub.example.com
#   2 - lookup for @.example.com
#   1 - lookup for @.com
#   0 - lookup for @.       (catchall)
MAILADDR_PRIORITIES = {
    "email": 10,
    "ip": 9,
    "wildcard_ip": 8,
    "cidr_network": 7,  # '192.168.1.0/24'. used in iRedAPD plugin
    # `amavisd_wblist`
    "wildcard_addr": 7,  # r'user@*'. used in iRedAPD plugin `amavisd_wblist`
    # as wildcard sender. e.g. 'user@*'
    "domain": 5,
    "subdomain": 3,
    "tld_domain": 2,
    "catchall_ip": 1,  # used in iRedAPD plugin `throttle`
    "catchall": 0,
}

# iRedAPD account priorities.
IREDAPD_ACCOUNT_PRIORITIES = {
    "email": 100,  # e.g. 'user@domain.com'. Highest priority
    "wildcard_addr": 90,  # e.g. `user@*`. used in plugin `amavisd_wblist`
    # as wildcard sender. e.g. 'user@*`
    "ip": 80,  # e.g. 173.254.22.21
    "wildcard_ip": 70,  # e.g. 173.254.22.*
    "cidr": 70,  # e.g. 173.254.22.0/24
    "domain": 60,  # e.g. @domain.com
    "subdomain": 50,  # e.g. @.domain.com
    "top_level_domain": 40,  # e.g. @com, @org
    "catchall": 0,  # '@.'. Lowest priority
}

# Access policies of mailing list (LDAP backends) and mail alias (SQL backends)
# Note: `allowedonly` is used in old iRedAdmin/iRedAPD releases, please use
#       `moderatorsonly` instead.
MAILLIST_ACCESS_POLICIES = [
    "public",
    "domain",
    "subdomain",
    "membersonly",
    "moderatorsonly",
    "allowedonly",  # Same
    "membersandmoderatorsonly",
]

# Access policies of mlmmj mailing list.
ML_ACCESS_POLICIES = [
    "public",
    "domain",
    "subdomain",
    "membersonly",
    "moderatorsonly",
    "membersandmoderatorsonly",
]


def is_auth_email(s) -> bool:
    try:
        s = str(s).strip()
    except UnicodeEncodeError:
        return False

    if regxes.cmp_auth_email.match(s):
        return True

    return False


def is_email(s) -> bool:
    try:
        s = str(s).strip()
    except UnicodeEncodeError:
        return False

    if regxes.cmp_email.match(s):
        return True

    # Check `[<IP>]` in domain part.
    parts = s.split("@", 1)
    if len(parts) != 2:
        return False

    if len(parts[0]) == 0 or len(parts[1]) == 0:
        return False

    domain = parts[1]
    if (domain[0] == "[") and (domain[-1] == "]"):
        ip = domain.lstrip("[").rstrip("]")
        if is_strict_ip(ip):
            return True

    return False


def is_domain(s) -> bool:
    try:
        s = str(s).lower()
    except:
        return False

    if len(set(s) & set("~!#$%^&*()+\\/ ")) > 0 or "." not in s:
        return False

    if regxes.cmp_domain.match(s):
        return True
    else:
        return False


def is_tld_domain(s) -> bool:
    s = str(s)

    if regxes.cmp_top_level_domain.match(s):
        return True
    else:
        return False


# Valid IP address
def is_ipv4(address) -> bool:
    """
    Returns True if `address` is a valid IPv4 address.

    >>> is_ipv4('192.168.1.0/24')
    False
    >>> is_ipv4('192.168.1.1')
    True
    >>> is_ipv4('192.168. 1.1')
    False
    >>> is_ipv4('192.168.1.800')
    False
    >>> is_ipv4('192.168.1.1000')
    False
    >>> is_ipv4('192.168.1')
    False
    >>> is_ipv4('::1')
    False
    """
    try:
        octets = address.split(".")
        if len(octets) != 4:
            return False

        for x in octets:
            if " " in x:
                return False

            if not (0 <= int(x) <= 255):
                return False

        if not (0 < int(octets[3]) <= 255):
            return False

        return True
    except:
        return False


def is_ipv6(address) -> bool:
    """
    Returns True if `address` is a valid IPv6 address.

    >>> is_ipv6('::')
    True
    >>> is_ipv6('aaaa:bbbb:cccc:dddd::1')
    True
    >>> is_ipv6('1:2:3:4:5:6:7:8:9:10')
    False
    >>> is_ipv6('12:10')
    False
    """
    try:
        socket.inet_pton(socket.AF_INET6, address)
    except (OSError, AttributeError, ValueError):
        return False

    return True


def is_strict_ip(s) -> bool:
    if is_ipv4(s) or is_ipv6(s):
        return True
    else:
        return False


def is_ip_or_network(address) -> bool:
    """Return True if `address` is a valid IP address or CIDR network."""
    if is_ipv4(address) or is_ipv6(address) or is_cidr_network(address):
        return True
    else:
        return False


def is_wildcard_ipv4(s) -> bool:
    if regxes.cmp_wildcard_ipv4.match(s):
        return True

    return False


def is_wildcard_addr(s) -> bool:
    if regxes.cmp_wildcard_addr.match(s):
        return True

    return False


def is_cidr_network(address) -> bool:
    """Return `True` if `address` is a CIDR network.

    >>> is_cidr_network('192.168.1.1')
    False
    >>> is_cidr_network('::1')
    False
    >>> is_cidr_network('192.168.1.0')
    False
    >>> is_cidr_network('192.168.1.0/32')
    True
    >>> is_cidr_network('2620:0:2d0:200::7')
    False
    >>> is_cidr_network('2620:0:2d0:200::7/128')
    True
    """
    if is_ipv4(address):
        return False

    if is_ipv6(address):
        return False

    if '/' not in address:
        # Not network.
        return False

    try:
        ipaddress.ip_network(str(address))
        return True
    except:
        return False


def is_list_with_ip_or_network(lst) -> bool:
    if not isinstance(lst, list):
        return False

    nl = [i for i in lst if is_ip_or_network(i)]
    if len(lst) == len(nl):
        return True
    else:
        # some element is invalid ip or network.
        return False


def is_valid_account_first_char(s) -> bool:
    if regxes.cmp_valid_account_first_char.match(s):
        return True

    return False


def is_mlid(s) -> bool:
    if regxes.cmp_mailing_list_id.match(s):
        return True

    return False


def is_ml_confirm_token(s) -> bool:
    if regxes.cmp_mailing_list_confirm_token.match(s):
        return True

    return False


def is_boolean(s) -> bool:
    """Return True if `s` is one of:

    - 'true' (string)
    - 'false' (string)
    - True (Python bool)
    - False (Python boolean)

    Otherwise return False.
    """
    try:
        s = str(s).strip().lower()
    except Exception:
        return False

    if s in ["true", "false"]:
        return True
    else:
        return False


def is_valid_mailbox_format(s) -> bool:
    """Check whether given mailbox format is one of `maildir`, `mdbox`, `sdbox`.
    Currently only 3 formats are supported.
    """
    if s in ["maildir", "mdbox", "sdbox"]:
        return True
    else:
        return False


def is_valid_mailbox_folder(s) -> bool:
    if s == "":
        return False

    if regxes.cmp_mailbox_folder.match(s):
        return True
    else:
        return False


def is_integer(s) -> bool:
    try:
        int(s)
        return True
    except Exception:
        return False


def is_positive_integer(s) -> bool:
    try:
        s = int(s)
        if s > 0:
            return True
    except:
        pass

    return False


def is_not_negative_integer(s) -> bool:
    try:
        s = int(s)
        if s >= 0:
            return True
    except:
        pass

    return False


# Translations
# Initialize object which used to stored all translations.
all_translations = {"en_US": gettext.NullTranslations()}


def ired_gettext(string):
    """Translate a given string to the language of the application."""
    lang = web.ctx.lang

    if lang in all_translations:
        translation = all_translations[lang]
    else:
        try:
            # Store new translation
            translation = gettext.translation(
                "iredadmin",
                os.path.abspath(os.path.dirname(__file__)) + "/../i18n",
                languages=[lang],
            )
            all_translations[lang] = translation
        except:
            translation = all_translations["en_US"]

    return translation.gettext(string)


def get_gmttime() -> str:
    # Convert local time to UTC
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())


def epoch_seconds_to_gmt(seconds, time_format=None) -> str:
    """Return local time by given seconds from epoch.

    >>> epoch_seconds_to_gmt(1000)
    '1970-01-01 00:16:40'
    >>> epoch_seconds_to_gmt(1000, time_format='%Y-%m-%d %H-%M-%S')
    '1970-01-01 00-16-40'
    """
    if not isinstance(seconds, int):
        try:
            seconds = int(seconds)
        except:
            return repr(seconds)

    if not time_format:
        time_format = "%Y-%m-%d %H:%M:%S"

    try:
        return time.strftime(time_format, time.gmtime(seconds))
    except:
        return str(seconds)


def epoch_days_to_date(days, time_format=None) -> str:
    """Convert epoch days to date."""
    if not isinstance(days, int):
        try:
            days = int(days)
        except:
            return ""

    if not time_format:
        time_format = "%Y-%m-%d"

    try:
        return time.strftime(time_format, time.gmtime(days * 24 * 60 * 60))
    except:
        return ""


def set_datetime_format(t, with_hour=True, time_format=None) -> str:
    """Format LDAP timestamp and Amavisd msgs.time_iso to YYYY-MM-DD HH:MM:SS.

    >>> set_datetime_format('20100925T113256Z')
    '2010-09-25 11:32:56'
    >>> set_datetime_format('20100925T113256Z', with_hour=False)
    '2010-09-25'
    >>> set_datetime_format('datetime.datetime(2020, 10, 25, 18, 58, 43, tzinfo=psycopg2.tz.FixedOffsetTimezone(offset=-420, name=None))')
    '2020-10-25 18:58:43'
    >>> set_datetime_format('datetime.datetime(2021, 9, 2, 15, 20, tzinfo=psycopg2.tz.FixedOffsetTimezone(offset=120, name=None))')
    '2021-09-02 15:20:00+02'
    >>> set_datetime_format('INVALID_TIME_STAMP')   # Return original string
    'INVALID_TIME_STAMP'
    """
    if t is None:
        return "--"
    else:
        t = str(t)

    _length = len(t)
    if not time_format:
        if not with_hour:
            time_format = "%Y-%m-%d"
        else:
            time_format = "%Y-%m-%d %H:%M:%S"

    if "T" not in t and t.endswith("Z"):
        # LDAP timestamp
        try:
            return time.strftime(time_format, time.strptime(t, "%Y%m%d%H%M%SZ"))
        except:
            pass

    elif ("T" in t) and t.endswith("Z"):
        # MySQL TIMESTAMP(): yyyymmddTHHMMSSZ
        try:
            return time.strftime(time_format, time.strptime(t, "%Y%m%dT%H%M%SZ"))
        except:
            pass

    elif (_length == 19) and ("-" in t) and (" " in t) and (":" in t):
        # MySQL NOW(): `yyyy-mm-dd HH:MM:SS`
        try:
            return time.strftime(time_format, time.strptime(t, "%Y-%m-%d %H:%M:%S"))
        except:
            pass
    elif (_length > 43) and t.startswith('datetime.datetime(') and 'tzinfo=' in t:
        # [DIRTY HACK] if `t` is the result of `repr()` like this:
        # "datetime.datetime(2020, 10, 25, 18, 58, 43, tzinfo=psycopg2.tz.FixedOffsetTimezone(offset=-420, name=None))"
        # "datetime.datetime(2020, 11, 17, 11, 31, 27, tzinfo=psycopg2.tz.FixedOffsetTimezone(offset=360, name=None))
        # Second is missing (which equals to "00"):
        #   "datetime.datetime(2020, 11, 17, 11, 31, tzinfo=psycopg2.tz.FixedOffsetTimezone(offset=360, name=None))
        try:
            # Extract time and offset seconds.
            p1 = re.compile(r'datetime.datetime\((\d{4}), (\d{1,2}), (\d{1,2}), (\d{1,2}), (\d{1,2}), (\d{1,2}), tzinfo=.*offset=([+-]*\d+),.*')
            if p1.match(t):
                mg = p1.match(t).groups()
            else:
                p2 = re.compile(r'datetime.datetime\((\d{4}), (\d{1,2}), (\d{1,2}), (\d{1,2}), (\d{1,2}), tzinfo=.*offset=([+-]*\d+),.*')
                mg = p2.match(t).groups()

            s = ' '.join(mg[:-1])
            offset_seconds = mg[-1]

            ts = time.strptime(s, "%Y %m %d %H %M %S")  # time.struct_time
            dt = datetime.datetime.fromtimestamp(time.mktime(ts))

            if offset_seconds.startswith('-'):
                seconds = int(offset_seconds[1:])
                dt2 = dt - datetime.timedelta(seconds=seconds)
            elif offset_seconds.startswith('+'):
                seconds = int(offset_seconds[1:])
                dt2 = dt + datetime.timedelta(seconds=seconds)
            else:
                dt2 = dt + datetime.timedelta(seconds=int(offset_seconds))

            return time.strftime(time_format, dt2.timetuple())
        except:
            pass

    if _length == 22:
        # PostgreSQL, time with time zone.
        # e.g. 2015-04-27 20:40:30-04
        t = t[:-3]
        try:
            return time.strftime(time_format, time.strptime(t, "%Y-%m-%d %H:%M:%S"))
        except:
            pass

    elif _length == 25:
        # PostgreSQL, time with time zone.
        # e.g. 2015-04-27 20:40:30-04:00
        t = t[:-6]
        try:
            return time.strftime(time_format, time.strptime(t, "%Y-%m-%d %H:%M:%S"))
        except:
            pass
    elif _length == 26:
        # PostgreSQL, time with million seconds.
        # e.g. 2015-04-27 20:40:30-xxxxxx
        t = t[:-7]
        try:
            return time.strftime(time_format, time.strptime(t, "%Y-%m-%d %H:%M:%S"))
        except:
            pass

    elif _length == 14:
        # ISO8601 UTC ascii time. Used in table: amavisd.msgs.
        try:
            return time.strftime(time_format, time.strptime(t, "%Y%m%d%H%M%S"))
        except:
            pass

    return t


def __bytes2str(b) -> str:
    """Convert object `b` to string.

    >>> __bytes2str("a")
    'a'
    >>> __bytes2str(b"a")
    'a'
    >>> __bytes2str(["a"])  # list: return `repr()`
    "['a']"
    >>> __bytes2str(("a",)) # tuple: return `repr()`
    "('a',)"
    >>> __bytes2str({"a"})  # set: return `repr()`
    "{'a'}"
    """
    if isinstance(b, str):
        return b

    if isinstance(b, (bytes, bytearray)):
        return b.decode()
    elif isinstance(b, memoryview):
        return b.tobytes().decode()
    else:
        return repr(b)


def bytes2str(b: Union[bytes, str, List, Tuple, Set, Dict])\
        -> Union[str, List[str], Tuple[str], Dict[Any, str]]:
    """Convert `b` from bytes-like type to string.

    - If `b` is a string object, returns original `b`.
    - If `b` is a bytes, returns `b.decode()`.

    bytes-like object, return `repr(b)` directly.

    >>> bytes2str("a")
    'a'
    >>> bytes2str(b"a")
    'a'
    >>> bytes2str(["a"])
    ['a']
    >>> bytes2str((b"a",))
    ('a',)
    >>> bytes2str({b"a"})
    {'a'}
    >>> bytes2str({"a": b"a"})      # used to convert LDAP query result.
    {'a': 'a'}
    """
    if isinstance(b, (list, web.db.ResultSet)):
        s = [bytes2str(i) for i in b]
    elif isinstance(b, tuple):
        s = tuple([bytes2str(i) for i in b])
    elif isinstance(b, set):
        s = {bytes2str(i) for i in b}
    elif isinstance(b, (dict, web.utils.Storage)):
        new_dict = {}
        for (k, v) in list(b.items()):
            new_dict[k] = bytes2str(v)  # v could be list/tuple/dict
        s = new_dict
    else:
        s = __bytes2str(b)

    return s


def __str2bytes(s) -> bytes:
    """Convert `s` from string to bytes."""
    if isinstance(s, bytes):
        return s
    elif isinstance(s, str):
        return s.encode()
    elif isinstance(s, (int, float)):
        return str(s).encode()
    else:
        return bytes(s)


def str2bytes(s):
    if isinstance(s, (list, web.db.ResultSet)):
        s = [str2bytes(i) for i in s]
    elif isinstance(s, tuple):
        s = tuple([str2bytes(i) for i in s])
    elif isinstance(s, set):
        s = {str2bytes(i) for i in s}
    elif isinstance(s, (dict, web.utils.Storage)):
        new_dict = {}
        for (k, v) in list(s.items()):
            new_dict[k] = str2bytes(v)  # v could be list/tuple/dict
        s = new_dict
    else:
        s = __str2bytes(s)

    return s


def generate_random_strings(length=10) -> str:
    """Create a random password of specified length"""
    if length <= 0:
        length = 10
    else:
        length = int(length)

    # Characters used to generate the random password
    # Few chars are removed to avoid confusion:
    #   - digits: 0, 1
    #   - letters: i, I, O
    chars = "23456789" + \
            "abcdefghjkmnpqrstuvwxyz" + \
            "23456789" + \
            "ABCDEFGHJKLMNPQRSTUVWXYZ" + \
            "23456789"

    s = ""
    for x in range(length):
        s += random.choice(chars)

    return s


def generate_maildir_path(mail: str,
                          hash_maildir=settings.MAILDIR_HASHED,
                          prepend_domain_name=settings.MAILDIR_PREPEND_DOMAIN,
                          append_timestamp=settings.MAILDIR_APPEND_TIMESTAMP,
                          ) -> str:
    """Generate path of mailbox."""
    username, domain = mail.lower().split("@", 1)

    # Get current timestamp.
    timestamp = ""
    if append_timestamp:
        timestamp = time.strftime("-%Y.%m.%d.%H.%M.%S")

    if hash_maildir:
        chars = [username[0]]

        _len_username = len(username)
        if _len_username == 1:
            chars += ["_", "_"]
        elif _len_username == 2:
            chars += [username[1], "_"]
        else:
            # _len_username >= 3
            chars += [username[1], username[2]]

        # Replace '.' and '~' by '_'
        for (index, char) in enumerate(chars):
            if char in [".", "~"]:
                chars[index] = "_"

        maildir = "{}/{}/{}/{}{}/".format(chars[0], chars[1], chars[2], username, timestamp)
    else:
        maildir = "{}{}/".format(username, timestamp)

    if prepend_domain_name:
        maildir = domain + "/" + maildir

    return maildir


def shadowlastchange_to_date(day, time_format="%Y-%m-%d %H:%M:%SZ") -> str:
    """Convert LDAP shadowLastChange value to date.

    >>> shadowlastchange_to_date(18500)
    '2020-08-26 00:00:00Z'
    >>> shadowlastchange_to_date(18500, time_format="%Y-%m-%d")
    '2020-08-26'
    >>> shadowlastchange_to_date(18500, time_format="%Y-%m-%d %H:%M")
    '2020-08-26 00:00'
    """
    if not isinstance(day, int):
        return "0000-00-00"

    _date = datetime.date(1970, 1, 1) + datetime.timedelta(day)
    if time_format:
        return _date.strftime(time_format)
    else:
        return _date.isoformat()


def reverse_amavisd_domain_names(domains=None) -> List[str]:
    """
    Reverse list of domain names to amavisd style.

    >>> reverse_amavisd_domain_names(['example.com', 'sub.example.com'])
    ['com.example', 'com.example.sub']
    """
    if not domains:
        return []

    domains = [str(d).lower() for d in domains if is_domain(d)]

    all_reversed = []
    for d in domains:
        rd = d.split(".")
        rd.reverse()
        all_reversed += [".".join(rd)]

    return all_reversed


def is_allowed_ip(client_ip, allowed_ip_list) -> bool:
    """Check whether given IP is part of given IP list.

    >>> is_allowed_ip('192.168.1.1', ['192.168.1.0/24', '172.16.0.0/8'])
    True
    >>> is_allowed_ip('192.168.1.1', ['10.0.0.0/8', '172.16.0.0/8'])
    False
    """
    if not allowed_ip_list:
        return False

    if client_ip in allowed_ip_list:
        return True

    _ip_obj = ipaddress.ip_address(str(client_ip))
    if _ip_obj.version == 4:
        # IP subnet: xx.xx.xx
        _ip_splited_parts = client_ip.split(r".")
        _ip_part4 = int(_ip_splited_parts[3])

        _ip_sub = ".".join(_ip_splited_parts[:3])
        if _ip_sub in allowed_ip_list:
            return True

        # IPv4 ranges: xx.xx.xx.xx-yy
        _ip_ranges = [x for x in allowed_ip_list if "-" in x]
        for _range in _ip_ranges:
            if not _range.startswith(_ip_sub + "."):
                continue

            try:
                (p1, p2, p3, p4) = _range.split(".")
                if "-" in p4:
                    (range_start, range_end) = p4.split("-")
                    _part4s = list(range(int(range_start), int(range_end) + 1))
                    if _ip_part4 in _part4s:
                        return True
            except:
                pass

    # IPv4/v6 networks
    _ip_networks = [x for x in allowed_ip_list if "/" in x]
    for _net in _ip_networks:
        try:
            _network = ipaddress.ip_network(str(_net))
            if _ip_obj in _network:
                return True
        except:
            pass

    return False


def self_service_login_redirect(username):
    # Possible redirect pages: preferences, quarantined, received, wblist, spampolicy.
    if settings.SELF_SERVICE_DEFAULT_PAGE == "preferences":
        raise web.seeother("/preferences")
    elif settings.SELF_SERVICE_DEFAULT_PAGE == "quarantined":
        raise web.seeother("/activities/quarantined/user/" + username)
    elif settings.SELF_SERVICE_DEFAULT_PAGE == "received":
        raise web.seeother("/activities/received/user/" + username)
    elif settings.SELF_SERVICE_DEFAULT_PAGE == "wblist":
        raise web.seeother("/preferences/wblist")
    elif settings.SELF_SERVICE_DEFAULT_PAGE == "spampolicy":
        raise web.seeother("/preferences/spampolicy")
    else:
        raise web.seeother("/preferences")


# Apply custom functions defined in `hooks.py`.
def apply_hook(hook_name, *args, **kwargs):
    try:
        from . import hooks

        if hook_name in hooks.__dict__:
            ret = hooks.__dict__[hook_name](*args, **kwargs)

            return True, ret
        else:
            return None, "HOOK_NOT_AVAILABLE"
    except ImportError:
        return None, "HOOK_NOT_AVAILABLE"
    except Exception as e:
        return False, repr(e)


def sendmail_with_cmd(from_address, recipients, message_text):
    """Send email with `sendmail` command (defined in CMD_SENDMAIL).

    :param recipients: a list/set/tuple of recipient email addresses, or a
                       string of a single mail address.
    :param message_text: encoded mail message.
    :param from_address: the From: address used while sending email.
    """
    if isinstance(recipients, (list, tuple, set)):
        recipients = ",".join(recipients)

    cmd = [settings.CMD_SENDMAIL, "-f", from_address, recipients]

    msg = str2bytes(message_text)
    try:
        p = subprocess.Popen(cmd, stdin=subprocess.PIPE)
        p.stdin.write(msg)
        p.stdin.close()
        p.wait()

        return True,
    except Exception as e:
        return False, repr(e)


def sendmail(recipients, message_text, from_address=None):
    """Send email through smtp or with command `sendmail`.

    :param recipients: a list/set/tuple of recipient email addresses.
    :param message_text: encoded mail message.
    :param from_address: the From: address used while sending email.
    """
    server = settings.NOTIFICATION_SMTP_SERVER
    port = settings.NOTIFICATION_SMTP_PORT
    user = settings.NOTIFICATION_SMTP_USER
    password = settings.NOTIFICATION_SMTP_PASSWORD
    starttls = settings.NOTIFICATION_SMTP_STARTTLS
    debug_level = settings.NOTIFICATION_SMTP_DEBUG_LEVEL

    if not from_address:
        from_address = user

    if server and port and user and password:
        # Send email through standard smtp protocol
        try:
            s = smtplib.SMTP(server, port)
            s.set_debuglevel(debug_level)

            if starttls:
                s.ehlo()
                s.starttls()
                s.ehlo()

            s.login(user, password)
            s.sendmail(from_address, recipients, message_text)
            s.quit()
            return True,
        except Exception as e:
            return False, repr(e)
    else:
        return sendmail_with_cmd(
            from_address=from_address,
            recipients=recipients,
            message_text=message_text,
        )


def is_valid_amavisd_address(addr):
    """Check whether given address is a valid Amavisd address.

    Valid address format:

    - email: single address. e.g. user@domain.com
    - domain: @domain.com
    - subdomain: entire domain and all sub-domains. e.g. @.domain.com
    - tld_domain: top level domain name. e.g. @.com, @.org.
    - catchall: catch all address. @.
    - ip: IPv4 or IPv6 address. Used in iRedAPD plugin `amavisd_wblist`
    - cidr_network: IPv4 or IPv6 CIDR network. Used in iRedAPD plugin `amavisd_wblist`
    - wildcard_addr: address with wildcard. e.g. 'user@*'. used in wblist.
    - wildcard_ip: wildcard IP addresses. e.g. 192.168.1.*.

    WARNING: don't forget to update MAILADDR_PRIORITIES in libs/iredutils.py
    for newly added address format.

    >>> is_valid_amavisd_address('user@domain.com')
    'email'
    >>> is_valid_amavisd_address('@domain.com')
    'domain'
    >>> is_valid_amavisd_address('@.domain.com')
    'subdomain'
    >>> is_valid_amavisd_address('@.sub.domain.com')
    'subdomain'
    >>> is_valid_amavisd_address('@.com')
    'tld_domain'
    >>> is_valid_amavisd_address('@.io')
    'tld_domain'
    >>> is_valid_amavisd_address('@.')
    'catchall'
    >>> is_valid_amavisd_address('192.168.1.1')
    'ip'
    >>> is_valid_amavisd_address('::1')
    'ip'
    >>> is_valid_amavisd_address('192.168.1.0/24')
    'cidr_network'
    >>> is_valid_amavisd_address('2620:0:2d0:200::7/128')
    'cidr_network'
    >>> is_valid_amavisd_address('user@*')
    'wildcard_addr'
    >>> is_valid_amavisd_address('192.168.1.*')
    'wildcard_ip'
    """
    addr = str(addr)

    if addr.startswith(r"@."):
        if addr == r"@.":
            return "catchall"
        else:
            domain = addr.split(r"@.", 1)[-1]

            if is_domain(domain):
                return "subdomain"
            elif is_tld_domain(domain):
                return "tld_domain"

    elif addr.startswith(r"@"):
        # entire domain
        domain = addr.split(r"@", 1)[-1]
        if is_domain(domain):
            return "domain"

    elif is_email(addr):
        # single email address
        return "email"

    elif is_strict_ip(addr):
        return "ip"
    elif is_cidr_network(addr):
        return "cidr_network"
    elif is_wildcard_addr(addr):
        return "wildcard_addr"
    elif is_wildcard_ipv4(addr):
        return "wildcard_ip"

    return False


def get_wblist_address_type(addr):
    """Check and return the type of white/blacklist address.

    Valid whitelist/blacklist address format:

    - email: single address. e.g. user@domain.com
    - domain: @domain.com
    - subdomain: entire domain and all sub-domains. e.g. @.domain.com
    - tld_domain: top level domain name. e.g. @.com, @.org.
    - catchall: catch all address. @.
    - ipv4, ipv6: IPv4 or IPv6 address. Used in iRedAPD plugin `amavisd_wblist`
    - cidr_network: CIDR format network

    >>> get_wblist_address_type('user@domain.com')
    'email'
    >>> get_wblist_address_type('@domain.com')
    'domain'
    >>> get_wblist_address_type('@.domain.com')
    'subdomain'
    >>> get_wblist_address_type('@.sub.domain.com')
    'subdomain'
    >>> get_wblist_address_type('@.com')
    'tld_domain'
    >>> get_wblist_address_type('@.io')
    'tld_domain'
    >>> get_wblist_address_type('@.')
    'catchall'
    >>> get_wblist_address_type('192.168.1.1')
    'ipv4'
    >>> get_wblist_address_type('::1')
    'ipv6'
    >>> get_wblist_address_type('2001:0db8:85a3:0000:0000:8a2e:0370:7334')
    'ipv6'
    >>> get_wblist_address_type('192.168.1.0')
    False
    >>> get_wblist_address_type('192.168.1.0/24')
    'cidr_network'
    >>> get_wblist_address_type('2620:0:2d0:200::7/128')
    'cidr_network'
    """
    addr = str(addr).lower()

    if addr.startswith(r"@."):
        if addr == r"@.":
            # Catch-all
            return "catchall"
        else:
            domain = addr.split(r"@.", 1)[-1]

            if is_domain(domain):
                # sub-domain
                return "subdomain"
            elif is_tld_domain(domain):
                # top-level domain name
                return "tld_domain"

    elif addr.startswith(r"@"):
        # entire domain
        domain = addr.split(r"@", 1)[-1]
        if is_domain(domain):
            # domain
            return "domain"

    elif is_email(addr):
        # single email address
        return "email"
    elif is_ipv4(addr):
        return "ipv4"
    elif is_ipv6(addr):
        return "ipv6"
    elif is_cidr_network(addr):
        # an valid ip address or cidr network
        return "cidr_network"
    elif is_wildcard_addr(addr):
        return "wildcard_addr"

    return False


def is_valid_wblist_address(addr) -> bool:
    if get_wblist_address_type(addr):
        return True
    else:
        return False


def is_valid_wblist_rdns_domain(domain) -> bool:
    """Return `True` is `domain` is a domain, sub-domain, or top-level domain.

    Valid wblist_rdns domain format:

    - domain: domain.com
    - subdomain: entire domain and all sub-domains. e.g. '.domain.com'
    - tld_domain: entire domain and all sub-domains. e.g. '.domain.com'

    >>> is_valid_wblist_rdns_domain("domain.com")
    True
    >>> is_valid_wblist_rdns_domain(".domain.com")
    True
    >>> is_valid_wblist_rdns_domain(".sub.domain.com")
    True
    >>> is_valid_wblist_rdns_domain(".com")
    True
    >>> is_valid_wblist_rdns_domain("user@domain.com")
    False
    >>> is_valid_wblist_rdns_domain("@domain.com")
    False
    >>> is_valid_wblist_rdns_domain("@.domain.com")
    False
    >>> is_valid_wblist_rdns_domain("@.com")
    False
    >>> is_valid_wblist_rdns_domain(".")
    False
    >>> is_valid_wblist_rdns_domain("@.")
    False
    """
    domain = str(domain).lower()

    if is_domain(domain):
        return True
    elif domain.startswith(r"."):
        _d = domain.lstrip(".")
        if is_domain(_d) or is_tld_domain(_d):
            return True

    return False


# Get priority from MAILADDR_PRIORITIES
def get_account_priority(account) -> int:
    priority = 0

    addr_type = is_valid_amavisd_address(account)
    if addr_type in MAILADDR_PRIORITIES:
        priority = MAILADDR_PRIORITIES[addr_type]

    return priority


def strip_mail_ext_address(mail, delimiters=None) -> str:
    """Remove '+extension' in email address.

    >>> strip_mail_ext_address('user+ext@domain.com')
    'user@domain.com'
    """

    if not delimiters:
        delimiters = settings.RECIPIENT_DELIMITERS

    (_local, _domain) = mail.split("@", 1)
    for delimiter in delimiters:
        if delimiter in _local:
            (_local, _ext) = _local.split(delimiter, 1)

    return _local + '@' + _domain


def lower_email_with_upper_ext_address(mail: str, delimiters=None) -> str:
    """Convert email address to lower cases, but keep the extension part in


    >>> lower_email_with_upper_ext_address("USER+EXT@DOMAIN.COM")
    'user+EXT@domain.com'
    """

    if not delimiters:
        delimiters = settings.RECIPIENT_DELIMITERS

    (_orig_user, _domain) = mail.split("@", 1)
    for delimiter in delimiters:
        if delimiter in _orig_user:
            (_user, _ext) = _orig_user.split(delimiter, 1)
            return _user.lower() + delimiter + _ext + "@" + _domain.lower()

    return str(mail)


def get_password_policies(db_settings=None) -> Dict:
    """Return a dict of password policies."""
    if not db_settings:
        params = [
            "password_has_letter",
            "password_has_uppercase",
            "password_has_number",
            "password_has_special_char",
        ]
        db_settings = get_settings_from_db(params=params)

    return {
        "has_letter": db_settings["password_has_letter"],
        "has_uppercase": db_settings["password_has_uppercase"],
        "has_number": db_settings["password_has_number"],
        "has_special_char": db_settings["password_has_special_char"],
        "special_characters": settings.PASSWORD_SPECIAL_CHARACTERS,
    }


def is_allowed_api_client(ip, db_settings=None) -> bool:
    _ip_list = []
    if not db_settings:
        db_settings = get_settings_from_db(params=["restful_api_clients"])
        _ip_list = db_settings["restful_api_clients"]

    if _ip_list:
        if not is_allowed_ip(client_ip=ip, allowed_ip_list=_ip_list):
            return False

    return True


def add_element_to_list(lst, e, sort=False):
    """Add non-duplicate element to list."""
    if e not in lst:
        lst.append(e)

        if sort:
            lst.sort()

    return lst


def remove_element_from_list(lst, e, sort=False):
    """Remove existing element from list."""
    if e in lst:
        lst.remove(e)

        if sort:
            lst.sort()

    return lst


# Get available languages.
def get_language_maps() -> Dict:
    # Get available languages file.
    rootdir = os.path.abspath(os.path.dirname(__file__)) + "/../"
    available_langs = [
        web.safestr(os.path.basename(v))
        for v in glob.glob(rootdir + "i18n/[a-z][a-z]_[A-Z][A-Z]")
        if os.path.basename(v) in l10n.langmaps
    ]

    available_langs += [
        web.safestr(os.path.basename(v))
        for v in glob.glob(rootdir + "i18n/[a-z][a-z]")
        if os.path.basename(v) in l10n.langmaps
    ]
    available_langs.sort()

    # Get language maps.
    languagemaps = {}
    for i in available_langs:
        if i in l10n.langmaps:
            languagemaps.update({i: l10n.langmaps[i]})

    return languagemaps


# List all parameters which all allowed to be modified on web UI.
# Define format and validators for parameter values.
# Format:
#   {'<param>': {'validators': [<func>, <func>, ...]}
#
# - Validator `<func>` is a function which validates input value and returns
#   True or False. If False, value will be discarded.
setting_kvs_map = {
    # Mailbox
    "mailbox_format": {"validators": [is_valid_mailbox_format]},
    "mailbox_folder": {"validators": [is_valid_mailbox_folder]},
    # Password
    "min_passwd_length": {"validators": [is_not_negative_integer]},
    "max_passwd_length": {"validators": [is_not_negative_integer]},
    "password_has_letter": {"validators": [is_boolean]},
    "password_has_uppercase": {"validators": [is_boolean]},
    "password_has_number": {"validators": [is_boolean]},
    "password_has_special_char": {"validators": [is_boolean]},
    # Login
    "global_admin_ip_list": {"validators": [is_list_with_ip_or_network]},
    "admin_login_ip_list": {"validators": [is_list_with_ip_or_network]},
    "restful_api_clients": {"validators": [is_list_with_ip_or_network]},
    # Clean up
    "amavisd_remove_maillog_in_days": {"validators": [is_positive_integer]},
    "amavisd_remove_quarantined_in_days": {"validators": [is_positive_integer]},
}


def get_settings_from_db(params=None, account=None, conn_iredadmin=None) -> Dict:
    """Get a dict of settings defined in both `settings.py` and SQL database.

    - `params` is a list/tuple/set of parameter names defined in settings.

        If `params` is given, returned dict contains only these params and
        their values. if param doesn't exist in both `settings.py` and SQL db,
        it will not present in returned dict.

    - `account` could be one of:
        - `global`: global setting
        - `<domain-name>`: per-domain setting
        - `<email>`: per-user setting

    Notes:

    - SQL settings will override the ones defined in `settings.py`.
    - Parameter names defined in `settings.py` will be converted to lower cases.
    """
    _settings = {}

    if not account:
        account = 'global'

    if params:
        # Read given parameter from `settings.py`:
        for param in params:
            if hasattr(settings, param):
                v = getattr(settings, param)
                _settings[param] = v
            elif hasattr(settings, param.upper()):
                v = getattr(settings, param.upper())
                _settings[param] = v
            else:
                pass

    else:
        suffixes = (
            "_db_host",
            "_db_port",
            "_db_name",
            "_db_user",
            "_db_password",
            "ldap_bind_dn",
            "ldap_bind_password",
        )

        # Read all settings from `settings.py`
        for (k, v) in inspect.getmembers(settings):
            # Ignore module builtin functions/attributes, and SQL/LDAP database
            # related parameters
            if k.startswith("__") or \
               k.endswith(suffixes) or \
               k in ["webmaster", "backend", "mlmmjadmin_api_auth_token"]:
                pass
            else:
                _settings[k.lower()] = v

    if not conn_iredadmin:
        if hasattr(web, "conn_iredadmin"):
            conn_iredadmin = web.conn_iredadmin
        else:
            conn_iredadmin = get_db_conn(settings.iredadmin_db_name, settings.backend)

    try:
        if params:
            qr = conn_iredadmin.select(
                "settings",
                vars={"account": account, "params": params},
                what="k,v",
                where="account=$account AND k IN $params",
            )
        else:
            qr = conn_iredadmin.select(
                "settings",
                vars={"account": account},
                where="account=$account",
            )

        for row in qr:
            k = str(row.k)
            try:
                _d = json.loads(row.v)
                if "value" in _d:
                    _settings[k] = _d["value"]
            except:
                pass
    except:
        pass

    # Remove unlisted parameters, invalid values.
    # Re-format values.
    for (k, v) in list(_settings.items()):
        if k not in setting_kvs_map:
            _settings.pop(k)
            continue

        _validators = setting_kvs_map[k].get("validators", [])
        for _validator in _validators:
            if not _validator(v):
                _settings.pop(k)
                break

            if _validator in [is_integer, is_positive_integer, is_not_negative_integer]:
                _settings[k] = int(v)

    return _settings


def store_settings_in_db(kvs=None, account=None, flush=False, conn=None):
    """Store settings in SQL table `iredadmin.settings`.

    - `kvs` is a dict which contains parameter names and their values.

        Value will be converted to JSON (`{"value": <value>}`) before stored
        in SQL db.

        If parameter value is None, parameter will be removed from SQL db.
        Value `True` and `False` will be saved.

    - `account` could be:
        - `global`: global setting
        - `<domain-name>`: per-domain setting
        - `<email>`: per-user setting

    - `flush` means rebuild all parameters. If `flush` is True, all parameters
      in sql db will be removed first, then only parameters specified in `kvs`
      will be rebuilt and stored.
    """
    if (not kvs) or (not isinstance(kvs, dict)):
        return True,

    if not account:
        account = "global"

    if not conn:
        conn = web.conn_iredadmin

    new_kvs = {}
    for (k, v) in list(kvs.items()):
        if k == "csrf_token":
            continue

        _validators = setting_kvs_map.get(k, {}).get("validators", [])
        if is_boolean in _validators:
            # if key exists in kvs, consider it as True.
            new_kvs[k] = True
        else:
            _is_valid = True
            for _validator in _validators:
                if not _validator(v):
                    _is_valid = False
                    break  # do not waste time to run the rest validators

            if _is_valid:
                if is_integer in _validators:
                    new_kvs[k] = int(v)
                else:
                    new_kvs[k] = v

    # Get parameters which are boolean but missing in kvs
    missing_boolean_params = [
        k
        for k in list(setting_kvs_map.keys())
        if is_boolean in setting_kvs_map[k].get("validators", {}) and k not in new_kvs
    ]

    for k in missing_boolean_params:
        new_kvs[k] = False

    if new_kvs:
        if flush:
            # Remove all existing parameters.
            conn.delete("settings", vars={"account": account}, where="account=$account")
        else:
            # Remove keys of `kvs`, not `new_kvs`.
            _params = list(kvs.keys())
            conn.delete(
                "settings",
                vars={"account": account, "params": _params},
                where="account=$account AND k IN $params",
            )

        # Insert all kvs
        try:
            rows = [
                {"account": account, "k": k, "v": json.dumps({"value": v})}
                for (k, v) in list(new_kvs.items())
            ]
            conn.multiple_insert("settings", values=rows)
        except Exception as e:
            return False, repr(e)

    return True,


def __is_allowed_login_ip(client_ip, check_global_admin=False) -> bool:
    if not client_ip:
        return False

    if check_global_admin:
        db_settings = get_settings_from_db(params=["global_admin_ip_list"])
        _ip_list = db_settings.get("global_admin_ip_list", [])
    else:
        db_settings = get_settings_from_db(params=["admin_login_ip_list"])
        _ip_list = db_settings.get("admin_login_ip_list", [])

    if _ip_list:
        if not is_allowed_ip(client_ip=client_ip, allowed_ip_list=_ip_list):
            return False

    return True


def is_allowed_admin_login_ip(client_ip) -> bool:
    return __is_allowed_login_ip(client_ip=client_ip, check_global_admin=False)


def is_allowed_global_admin_login_ip(client_ip) -> bool:
    return __is_allowed_login_ip(client_ip=client_ip, check_global_admin=True)


def get_db_conn(db_name, sql_dbn):
    try:
        host = settings.__dict__[db_name + '_db_host']
        port = int(settings.__dict__[db_name + '_db_port'])
        db = settings.__dict__[db_name + '_db_name']
        user = settings.__dict__[db_name + '_db_user']
        pw = settings.__dict__[db_name + '_db_password']

        if sql_dbn == 'postgres':
            conn = web.database(
                dbn=sql_dbn,
                host=host,
                port=port,
                db=db,
                user=user,
                pw=pw,
            )
        else:
            # sql_dbn == 'mysql'
            conn = web.database(
                dbn=sql_dbn,
                host=host,
                port=port,
                db=db,
                user=user,
                pw=pw,
                charset='utf8',
            )

        conn.supports_multiple_insert = True
        return conn
    except:
        return None
