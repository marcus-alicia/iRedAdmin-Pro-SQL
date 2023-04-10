import web
from controllers import decorators

from libs.iredutils import is_valid_wblist_rdns_domain
from libs.iredapd import wblist_rdns, wblist_senderscore


class WBListRDNS:
    @decorators.require_global_admin
    def GET(self):
        # Get wblist records
        (_status, _result) = wblist_rdns.get_wblist_rdns()
        if not _status:
            raise web.seeother('/domains?msg=%s' % web.urlquote(_result))

        whitelists = _result['whitelists']
        blacklists = _result['blacklists']

        return web.render('iredapd/wblist/rdns.html',
                          whitelists=whitelists,
                          blacklists=blacklists,
                          msg=web.input().get('msg'))

    @decorators.require_global_admin
    def POST(self):
        form = web.input()

        whitelists = [str(i).lower()
                      for i in form.get('whitelists', '').splitlines()
                      if is_valid_wblist_rdns_domain(i)]
        whitelists = list(set(whitelists))

        blacklists = [str(i).lower()
                      for i in form.get('blacklists', '').splitlines()
                      if is_valid_wblist_rdns_domain(i)]
        blacklists = list(set(blacklists))

        (_status, _result) = wblist_rdns.reset_wblist_rdns(whitelists=whitelists, blacklists=blacklists)
        if _status:
            raise web.seeother('/system/wblist/rdns?msg=UPDATED')
        else:
            raise web.seeother('/system/wblist/rdns?msg=%s' % web.urlquote(_result))


class WBListSenderScore:
    @decorators.require_global_admin
    def GET(self):
        # Get wblist records
        (_status, _result) = wblist_senderscore.get_whitelists()
        if not _status:
            raise web.seeother('/domains?msg=%s' % web.urlquote(_result))

        total = _result['total']
        ips = _result['ips']

        return web.render('iredapd/wblist/senderscore.html',
                          total=total,
                          ips=ips,
                          msg=web.input().get('msg'))

    @decorators.require_global_admin
    def POST(self):
        form = web.input()

        whitelists = [str(i).lower()
                      for i in form.get('whitelists', '').splitlines()
                      if is_valid_wblist_rdns_domain(i)]
        whitelists = list(set(whitelists))

        blacklists = [str(i).lower()
                      for i in form.get('blacklists', '').splitlines()
                      if is_valid_wblist_rdns_domain(i)]
        blacklists = list(set(blacklists))

        (_status, _result) = wblist_rdns.reset_wblist_rdns(whitelists=whitelists, blacklists=blacklists)
        if _status:
            raise web.seeother('/system/wblist/senderscore?msg=UPDATED')
        else:
            raise web.seeother('/system/wblist/senderscore?msg=%s' % web.urlquote(_result))
