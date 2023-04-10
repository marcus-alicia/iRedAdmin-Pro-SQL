import web

from libs import iredutils

# `4102444799` seconds since 1970-01-01 is '2099-12-31 23:59:59'.
# It's a trick to use this time as whitelist and not cleaned by
# script `tools/cleanup_db.py`.
# It's ok to use any long epoch seconds to avoid cleanup, but we use this
# hard-coded value for easier management.
expire_epoch_seconds = 4102444799


def get_whitelists():
    total = 0
    ips = []

    try:
        qr = web.conn_iredapd.select(
            "senderscore_cache",
            vars={'seconds': expire_epoch_seconds},
            what='COUNT(client_address) AS total',
            where="time=$seconds",
        )
        total = qr[0].total

        if total:
            qr = web.conn_iredapd.select(
                "senderscore_cache",
                vars={'seconds': expire_epoch_seconds},
                what='client_address',
                where="time=$seconds",
            )

            ips = [i.client_address for i in qr]

        return True, {'total': total, 'ips': ips}
    except Exception as e:
        return False, repr(e)


def filter_whitelisted_ips(ips):
    # Return a list of whitelisted IP addresses of given ones.
    ips = [i for i in ips if iredutils.is_strict_ip(i)]

    try:
        qr = web.conn_iredapd.select(
            "senderscore_cache",
            vars={'ips': ips, 'seconds': expire_epoch_seconds},
            what='client_address',
            where="client_address IN $ips AND time=$seconds",
        )

        ips = [i.client_address for i in qr]
        return True, ips
    except Exception as e:
        return False, repr(e)


def whitelist_ips(ips):
    # Whitelist given IP addresses.
    ips = [i for i in ips if iredutils.is_strict_ip(i)]

    if not ips:
        return True,

    # Remove existing records first.
    try:
        web.conn_iredapd.delete("senderscore_cache",
                                vars={'ips': ips},
                                where="client_address IN $ips")

        rows = []
        for ip in ips:
            rows += [{'client_address': ip,
                      'score': 100,
                      'time': expire_epoch_seconds}]

        # Insert whitelists.
        web.conn_iredapd.multiple_insert("senderscore_cache", rows)

        return True,
    except Exception as e:
        return False, repr(e)
