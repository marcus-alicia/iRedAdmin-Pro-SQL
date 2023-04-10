# Author: Zhang Huangbin <zhb@iredmail.org>

from libs import iredutils
from libs.iredapd import throttle as iredapd_throttle
from libs.iredapd import greylist as iredapd_greylist


def delete_settings_for_removed_users(mails):
    try:
        iredapd_greylist.delete_settings_for_removed_users(mails=mails)
        iredapd_throttle.delete_settings_for_removed_users(mails=mails)

        return True,
    except Exception as e:
        return False, repr(e)


def delete_settings_for_removed_domains(domains):
    domains = [str(d).lower() for d in domains if iredutils.is_domain(d)]

    if not domains:
        return True,

    for d in domains:
        iredapd_throttle.delete_settings_for_removed_domain(domain=d)
        iredapd_greylist.delete_settings_for_removed_domain(domain=d)

    return True,
