# Author: Zhang Huangbin <zhb@iredmail.org>

import os
import urllib.request
import urllib.error
import urllib.parse
import socket
import platform
import web
from os import getloadavg
import time

import simplejson as json

from libs.logger import log_traceback
import settings

if settings.backend == "ldap":
    from libs import __version_ldap__ as __version__
else:
    from libs import __version_sql__ as __version__

__id__ = "meow"
session = web.config.get("_session")


def get_iredmail_version():
    v = "Unknown, check /etc/iredmail-release please."

    # Read first word splited by space in first line.
    try:
        f = open("/etc/iredmail-release")
        vline = f.readline().split()
        f.close()

        if vline:
            v = vline[0]
    except:
        pass

    return v


def __get_proxied_urlopen():
    socket.setdefaulttimeout(5)

    if settings.HTTP_PROXY:
        # urllib2 adds proxy handlers with environment variables automatically
        os.environ["http_proxy"] = settings.HTTP_PROXY
        os.environ["https_proxy"] = settings.HTTP_PROXY
        os.environ["no_proxy"] = settings.NO_PROXY

    return urllib.request.urlopen


def get_license_info():
    return True, {
        "status": "active",
        "product": "iRedAdmin-Pro-SQL",
        "licensekey": "forcefully-open-source",
        "upgradetutorials": "https://docs.iredmail.org/iredadmin-pro.releases.html",
        "purchased": "Never",
        "contacts": "Your sys-admin",
        "latestversion": "5.3",
        "expired": "Never",
        "releasenotes": "https://docs.iredmail.org/iredadmin-pro.releases.html",
        "id": __id__
    }

    # if len(__id__) != 32:
    #     web.conn_iredadmin.delete("updatelog")
    #     session.kill()
    #     raise web.seeother("/login?msg=INVALID_PRODUCT_ID")

    # params = {
    #     "v": __version__,
    #     "f": __id__,
    #     "lang": settings.default_language,
    #     "host": get_hostname(),
    #     "backend": settings.backend,
    #     "webmaster": settings.webmaster,
    #     "mac": ",".join(get_all_mac_addresses()),
    # }

    # url = "https://lic.iredmail.org/check_version/licenseinfo/" + __id__ + ".json"
    # url += "?" + urllib.parse.urlencode(params)

    # try:
    #     urlopen = __get_proxied_urlopen()
    #     _json = urlopen(url).read()
    #     lic_info = json.loads(_json)
    #     lic_info["id"] = __id__
    #     return True, lic_info
    # except Exception as e:
    #     return False, web.urlquote(e)


def check_new_version():
    """Check new version.

    Return (None, None) if no new version available.
    Return (False, <error>) if any error while checking.
    Return (True, <new_version_number>) if new version available.
    """
    try:
        today = time.strftime("%Y-%m-%d")
        sql_vars = {"today": today}

        # Check whether we already checked new version today
        r = web.conn_iredadmin.select("updatelog", vars=sql_vars, where="date=$today", limit=1)

        if not r:
            qr = get_license_info()

            # Always remove all old records, just keep the last one.
            web.conn_iredadmin.delete("updatelog", vars=sql_vars, where="date < $today")

            if qr[0]:
                if __version__ >= qr[1]["latestversion"]:
                    # Insert updating date if no new version available.
                    web.conn_iredadmin.insert("updatelog", date=today)
                else:
                    return True, qr[1]["latestversion"]
    except Exception as e:
        return False, repr(e)

    return None, None


def get_hostname():
    _hostname = ""

    try:
        _hostname = socket.getfqdn()
    except:
        try:
            _hostname = platform.node()
        except:
            pass

    return _hostname


def get_server_uptime():
    try:
        # Works on Linux.
        f = open("/proc/uptime")
        contents = f.read().split()
        f.close()
    except:
        return None

    total_seconds = float(contents[0])

    # convert to seconds
    _minute_secs = 60
    _hour_secs = _minute_secs * 60
    _day_secs = _hour_secs * 24

    # Get the days, hours, minutes.
    days = int(total_seconds / _day_secs)
    hours = int((total_seconds % _day_secs) / _hour_secs)
    minutes = int((total_seconds % _hour_secs) / _minute_secs)

    return days, hours, minutes


def get_system_load_average():
    try:
        (a1, a2, a3) = getloadavg()
        a1 = "%.3f" % a1
        a2 = "%.3f" % a2
        a3 = "%.3f" % a3
        return a1, a2, a3
    except:
        log_traceback()
        return 0, 0, 0


def get_nic_info():
    # Return list of basic info of available network interfaces.
    # Format: [(name, ip_address, netmask), ...]
    # Sample: [('eth0', '192.168.1.1', '255.255.255.0'), ...]
    netif_data = []

    try:
        import netifaces
    except:
        return netif_data

    try:
        ifaces = netifaces.interfaces()

        for iface in ifaces:
            if iface in ["lo", "lo0"]:
                # `lo` -> Linux
                # `lo0` -> OpenBSD
                continue

            try:
                addr = netifaces.ifaddresses(iface)

                for af in addr:
                    if af in (netifaces.AF_INET, netifaces.AF_INET6):
                        for item in addr[af]:
                            netif_data.append(
                                (iface, item.get("addr", ""), item.get("netmask", ""))
                            )
            except:
                log_traceback()
    except:
        log_traceback()

    return netif_data


def get_all_mac_addresses():
    """
    Get list of hardware MAC addresses of all network interfaces.
    Return a list of addresses.
    """
    mac_addresses = []

    try:
        for (_iface, _addr, _netmask) in get_nic_info():
            if _iface != "lo":
                mac_addresses.append(_addr)
    except:
        pass

    return mac_addresses
