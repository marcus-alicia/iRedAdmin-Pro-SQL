from base64 import b64decode
import web
from controllers import decorators
from controllers.utils import api_render

from libs import iredutils
from libs.logger import log_activity


class Banned:
    @decorators.require_global_admin
    def GET(self):
        _qr = web.conn_f2b.select(
            'banned',
            what='id, ip, rdns, ports, jail, country, failures, timestamp, remove',
            order='ip',
        )
        rows = list(_qr)

        return web.render('fail2ban/banned.html', rows=rows)


class UnbanIP:
    """Unban given IP address, or the IP addresses submitted by form.

    Note: It returns JSON.
    """
    @decorators.require_global_admin
    def DELETE(self, ip=None):
        if ip:
            ips = [ip]
        else:
            # Get IP addresses from web form.
            form = web.input(ip=[])
            ips = form.get('ip', [])

        ips = [ip for ip in ips if iredutils.is_strict_ip(ip)]

        if not ips:
            return api_render(True)

        try:
            web.conn_f2b.update(
                'banned',
                vars={"ips": ips},
                remove=1,
                where="ip IN $ips",
            )

            log_activity(msg="Unbanned: " + ', '.join(ips),
                         event='unban')

            return api_render(True)
        except Exception as e:
            return api_render((False, repr(e)))


class MatchedLogLines:
    @decorators.require_global_admin
    def GET(self, record_id):
        _qr = web.conn_f2b.select(
            'banned',
            vars={'id': record_id},
            what='loglines',
            where='id=$id',
            limit=1,
        )

        if _qr:
            loglines = _qr[0]['loglines']

            # Assume its base64 encoded, try to decode it.
            if loglines:
                try:
                    loglines = iredutils.bytes2str(b64decode(loglines))
                except:
                    pass
        else:
            loglines = 'NO_MATCHED_LOG_LINES'

        return web.render('fail2ban/matched_log_lines.html', loglines=loglines)
