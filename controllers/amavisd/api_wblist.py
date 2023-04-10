import web

from controllers.utils import api_render

from libs import iredutils, form_utils
from libs.amavisd import wblist as lib_wblist
import settings

session = web.config.get('_session')


if settings.backend == 'ldap':
    from libs.ldaplib.general import is_domain_admin
else:
    from libs.sqllib.general import is_domain_admin


def verify_permission(account):
    account = str(account).lower()

    if account == 'global':
        if not session.get('is_global_admin'):
            return False, 'PERMISSION_DENIED'

        wblist_account = '@.'
    else:
        if iredutils.is_domain(account):
            domain = account
            wblist_account = '@' + account
        elif iredutils.is_email(account):
            domain = account.split('@', 1)[-1]
            wblist_account = account
        else:
            return False, 'INVALID_ACCOUNT'

        if not is_domain_admin(domain=domain, admin=session.get('username'), conn=None):
            return False, 'PERMISSION_DENIED'

    return True, wblist_account


def get_inout_wb(inout, wb):
    _is_in_wl = False
    _is_in_bl = False
    _is_out_wl = False
    _is_out_bl = False
    if inout == 'inbound':
        if wb == 'whitelist':
            _is_in_wl = True
        else:
            _is_in_bl = True
    else:
        if wb == 'whitelist':
            _is_out_wl = True
        else:
            _is_out_bl = True

    return {'is_in_wl': _is_in_wl,
            'is_in_bl': _is_in_bl,
            'is_out_wl': _is_out_wl,
            'is_out_bl': _is_out_bl}


class APIWBList:
    def GET(self, inout, wb, account):
        """Get existing wblist.

        curl -X GET -i -b cookie.txt https://<server>/api/wblist/inbound/whitelist/global
        curl -X GET -i -b cookie.txt https://<server>/api/wblist/inbound/blacklist/global
        curl -X GET -i -b cookie.txt https://<server>/api/wblist/outbound/whitelist/global
        curl -X GET -i -b cookie.txt https://<server>/api/wblist/outbound/blacklist/global
        """
        _qr = verify_permission(account)
        if not _qr[0]:
            return api_render(_qr)

        wblist_account = _qr[1]
        inout_wb = get_inout_wb(inout=inout, wb=wb)

        qr = lib_wblist.get_wblist(
            account=wblist_account,
            whitelist=inout_wb['is_in_wl'],
            blacklist=inout_wb['is_in_bl'],
            outbound_whitelist=inout_wb['is_out_wl'],
            outbound_blacklist=inout_wb['is_out_bl'],
        )

        if not qr[0]:
            return api_render(qr)

        result = qr[1]
        if inout_wb['is_in_wl']:
            addresses = result['inbound_whitelists']
        elif inout_wb['is_in_bl']:
            addresses = result['inbound_blacklists']
        elif inout_wb['is_out_wl']:
            addresses = result['outbound_whitelists']
        else:
            # inout_wb['is_out_bl']
            addresses = result['outbound_blacklists']

        return api_render((True, addresses))

    def POST(self, inout, wb, account):
        """Create new wblist.

        curl -X POST ... \
                -d "addresses=user@domain.com,user2@domain.com" \
                https://<server>/api/wblist/inbound/whitelist/global

        curl -X POST ... \
                -d "addresses=user@domain.com,user2@domain.com" \
                https://<server>/api/wblist/inbound/blacklist/global

        curl -X POST ... \
                -d "addresses=user@domain.com,user2@domain.com" \
                https://<server>/api/wblist/outbound/whitelist/global

        curl -X POST ... \
                -d "addresses=user@domain.com,user2@domain.com" \
                https://<server>/api/wblist/outbound/blacklist/global
        """
        _qr = verify_permission(account)
        if not _qr[0]:
            return api_render(_qr)

        wblist_account = _qr[1]
        inout_wb = get_inout_wb(inout=inout, wb=wb)

        form = web.input(_unicode=False)
        _addresses = form_utils.get_multi_values_from_api(form=form, input_name='addresses')
        _addresses = [i for i in _addresses if iredutils.is_valid_amavisd_address(i)]

        d = {}
        for (k, v) in list(inout_wb.items()):
            _name = k.replace("is_", "")
            if v is True:
                d[_name] = _addresses
            else:
                d[_name] = None

        qr = lib_wblist.add_wblist(
            account=wblist_account,
            wl_senders=d["in_wl"],
            bl_senders=d["in_bl"],
            wl_rcpts=d["out_wl"],
            bl_rcpts=d["out_bl"],
            flush_before_import=False,
        )

        return api_render(qr)

    def PUT(self, inout, wb, account):
        # Delete addresses
        _qr = verify_permission(account)
        if not _qr[0]:
            return api_render(_qr)

        wblist_account = _qr[1]
        inout_wb = get_inout_wb(inout=inout, wb=wb)

        form = web.input(_unicode=False)
        _addresses = form_utils.get_multi_values_from_api(form=form, input_name='addresses')
        _addresses = [i for i in _addresses if iredutils.is_valid_amavisd_address(i)]

        d = {}
        for (k, v) in list(inout_wb.items()):
            _name = k.replace("is_", "")
            if v is True:
                d[_name] = _addresses
            else:
                d[_name] = None

        qr = lib_wblist.delete_wblist(
            account=wblist_account,
            wl_senders=d["in_wl"],
            bl_senders=d["in_bl"],
            wl_rcpts=d["out_wl"],
            bl_rcpts=d["out_bl"],
        )

        return api_render(qr)

    def DELETE(self, inout, wb, account):
        _qr = verify_permission(account)
        if not _qr[0]:
            return api_render(_qr)

        wblist_account = _qr[1]
        inout_wb = get_inout_wb(inout=inout, wb=wb)

        qr = lib_wblist.delete_all_wblist(
            account=wblist_account,
            wl_senders=inout_wb['is_in_wl'],
            bl_senders=inout_wb['is_in_bl'],
            wl_rcpts=inout_wb['is_out_wl'],
            bl_rcpts=inout_wb['is_out_bl'],
        )

        return api_render(qr)
