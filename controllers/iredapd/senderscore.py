from controllers import decorators
from controllers.utils import api_render
from libs.iredapd import wblist_senderscore


class WhitelistIPForSenderScore:
    @decorators.require_global_admin
    def PUT(self, ip):
        """Whitelist given IP address for senderscore.

        curl -X PUT -i -b cookie.txt -d "ip=x.x.x.x" https://<server>/api/wblist/senderscore/whitelist/<ip>
        """
        qr = wblist_senderscore.whitelist_ips(ips=[ip])
        return api_render(qr)
