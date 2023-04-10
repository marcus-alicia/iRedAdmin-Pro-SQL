# Author: Zhang Huangbin <zhb@iredmail.org>

import settings
from libs.regxes import email as e, domain as d

# fmt: off
urls = [
    # Search activity logs.
    '/activities/search', 'controllers.amavisd.log.SearchLog',

    # View log of sent/received mails
    '/activities/(received|sent)', 'controllers.amavisd.log.InOutMails',
    r'/activities/(received|sent)/page/(\d+)', 'controllers.amavisd.log.InOutMails',

    # Per-user activities
    '/activities/(received|sent)/(user)/(%s)' % e, 'controllers.amavisd.log.InOutMailsPerAccount',
    r'/activities/(received|sent)/(user)/(%s)/page/(\d+)' % e, 'controllers.amavisd.log.InOutMailsPerAccount',
    # Per-domain activities
    '/activities/(received|sent)/(domain)/(%s)' % d, 'controllers.amavisd.log.InOutMailsPerAccount',
    r'/activities/(received|sent)/(domain)/(%s)/page/(\d+)' % d, 'controllers.amavisd.log.InOutMailsPerAccount',

    # Quarantined mails
    '/activities/quarantined', 'controllers.amavisd.log.QuarantinedMails',
    r'/activities/quarantined/page/(\d+)', 'controllers.amavisd.log.QuarantinedMails',
    '/activities/quarantined/(spam|virus|banned|badheader|badmime|clean)', 'controllers.amavisd.log.QuarantinedMails',
    r'/activities/quarantined/(spam|virus|banned|badheader|badmime|clean)/page/(\d+)', 'controllers.amavisd.log.QuarantinedMails',
    # Per-user quarantined mails
    r'/activities/quarantined/(user)/(%s)' % e, 'controllers.amavisd.log.QuarantinedMailsPerAccount',
    r'/activities/quarantined/(user)/(%s)/page/(\d+)' % e, 'controllers.amavisd.log.QuarantinedMailsPerAccount',
    '/activities/quarantined/(user)/(%s)/(spam|virus|banned|badheader|badmime|clean)' % e, 'controllers.amavisd.log.QuarantinedMailsPerAccount',
    r'/activities/quarantined/(user)/(%s)/(spam|virus|banned|badheader|badmime|clean)/page/(\d+)' % e, 'controllers.amavisd.log.QuarantinedMailsPerAccount',
    # Per-domain quarantined mails
    '/activities/quarantined/(domain)/(%s)' % d, 'controllers.amavisd.log.QuarantinedMailsPerAccount',
    r'/activities/quarantined/(domain)/(%s)/page/(\d+)' % d, 'controllers.amavisd.log.QuarantinedMailsPerAccount',
    '/activities/quarantined/(domain)/(%s)/(spam|virus|banned|badheader|badmime|clean)' % d, 'controllers.amavisd.log.QuarantinedMailsPerAccount',
    r'/activities/quarantined/(domain)/(%s)/(spam|virus|banned|badheader|badmime|clean)/page/(\d+)' % d, 'controllers.amavisd.log.QuarantinedMailsPerAccount',

    # Get RAW message of quarantined mail by mail_id.
    '/activities/quarantined/raw/(.*)', 'controllers.amavisd.log.GetRawMessageOfQuarantinedMail',

    # Activity management
    '/activities/sender/(%s)' % e, 'controllers.amavisd.log.ActivityManagement',

    # Spam policies.
    # Global spam policy (recipient = '@.')
    '/system/spampolicy', 'controllers.amavisd.spampolicy.SpamPolicy',
    # per-domain spam policy (recipient = '@domain.com')
    '/system/spampolicy/(%s$)' % d, 'controllers.amavisd.spampolicy.SpamPolicy',
    # per-user spam policy (recipient = '@domain.com')
    '/system/spampolicy/(%s$)' % e, 'controllers.amavisd.spampolicy.SpamPolicy',

    # global wblist
    '/create/wblist', 'controllers.amavisd.wblist.Create',
    '/system/wblist', 'controllers.amavisd.wblist.GlobalWBList',

    # Per-user preferences: wblist, spam control
    '/preferences/wblist', 'controllers.amavisd.wblist.UserWBList',
    '/preferences/spampolicy', 'controllers.amavisd.spampolicy.SpamPolicy',
]

# API Interfaces
if settings.ENABLE_RESTFUL_API:
    urls += [
        # Global, per-domain, per-user spam policy
        '/api/spampolicy/(global)', 'controllers.amavisd.spampolicy.APISpamPolicy',
        '/api/spampolicy/(domain)/(%s$)' % d, 'controllers.amavisd.spampolicy.APISpamPolicy',
        '/api/spampolicy/(user)/(%s$)' % e, 'controllers.amavisd.spampolicy.APISpamPolicy',

        '/api/wblist/(inbound|outbound)/(whitelist|blacklist)/(global)', 'controllers.amavisd.api_wblist.APIWBList',
        '/api/wblist/(inbound|outbound)/(whitelist|blacklist)/(%s$)' % d, 'controllers.amavisd.api_wblist.APIWBList',
        '/api/wblist/(inbound|outbound)/(whitelist|blacklist)/(%s$)' % e, 'controllers.amavisd.api_wblist.APIWBList',
    ]
# fmt: on
