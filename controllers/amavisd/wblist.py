# Author: Zhang Huangbin <zhb@iredmail.org>

import web
from controllers import decorators
from libs.amavisd import get_wblist_from_form, wblist as lib_wblist

session = web.config.get('_session')


def render_wblist(account, template):
    whitelists = []
    blacklists = []
    outbound_whitelists = []
    outbound_blacklists = []

    qr = lib_wblist.get_wblist(account=account)
    if qr[0]:
        whitelists = qr[1]['inbound_whitelists']
        blacklists = qr[1]['inbound_blacklists']
        outbound_whitelists = qr[1]['outbound_whitelists']
        outbound_blacklists = qr[1]['outbound_blacklists']

    return web.render(template,
                      whitelists=whitelists,
                      blacklists=blacklists,
                      outbound_whitelists=outbound_whitelists,
                      outbound_blacklists=outbound_blacklists,
                      msg=web.input().get('msg'))


def update_wblist_from_form(form,
                            account,
                            post_url,
                            success_msg,
                            flush_before_import=False):
    wl_senders = get_wblist_from_form(form, 'wl_sender')
    bl_senders = get_wblist_from_form(form, 'bl_sender')
    wl_rcpts = get_wblist_from_form(form, 'wl_rcpt')
    bl_rcpts = get_wblist_from_form(form, 'bl_rcpt')

    qr = lib_wblist.add_wblist(account=account,
                               wl_senders=wl_senders,
                               bl_senders=bl_senders,
                               wl_rcpts=wl_rcpts,
                               bl_rcpts=bl_rcpts,
                               flush_before_import=flush_before_import)

    if qr[0]:
        raise web.seeother(post_url + '?msg=' + success_msg)
    else:
        raise web.seeother(post_url + '?msg=%s' % web.urlquote(qr[1]))


# Add global white/blacklists
class Create:
    @decorators.require_global_admin
    def GET(self):
        return web.render('amavisd/wblist/create.html',
                          msg=web.input().get('msg'))

    @decorators.require_global_admin
    def POST(self):
        form = web.input()

        return update_wblist_from_form(form=form,
                                       account='@.',
                                       post_url='/create/wblist',
                                       success_msg='WBLIST_CREATED',
                                       flush_before_import=False)


class GlobalWBList:
    @decorators.require_global_admin
    def GET(self):
        return render_wblist(account='@.', template='amavisd/wblist/global.html')

    @decorators.require_global_admin
    def POST(self):
        form = web.input()
        return update_wblist_from_form(form=form,
                                       account='@.',
                                       post_url='/system/wblist',
                                       success_msg='WBLIST_UPDATED',
                                       flush_before_import=True)


class UserWBList:
    @decorators.require_preference_access('wblist')
    @decorators.require_login
    def GET(self):
        account = session['username']
        return render_wblist(account=account,
                             template='amavisd/wblist/user.html')

    @decorators.require_preference_access('wblist')
    @decorators.require_login
    def POST(self):
        account = session['username']
        form = web.input()
        return update_wblist_from_form(form=form,
                                       account=account,
                                       post_url='/preferences/wblist',
                                       success_msg='WBLIST_UPDATED',
                                       flush_before_import=True)
