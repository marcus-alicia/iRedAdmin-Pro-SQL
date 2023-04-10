# Author: Zhang Huangbin <zhb@iredmail.org>

import settings
from libs.regxes import email as e, domain as d, ip

# fmt: off
urls = [
    # Throttling
    '/system/throttle', 'controllers.iredapd.throttle.GlobalThrottle',
    # Greylisting
    '/system/greylisting', 'controllers.iredapd.greylist.DefaultGreylisting',
    # Greylisting tracking data
    '/system/greylisting/tracking/domain/(%s)' % d, 'controllers.iredapd.greylist.GreylistingRawTrackingData',
    # White/blacklist based on rDNS
    '/system/wblist/rdns', 'controllers.iredapd.wblist_rdns.WBListRDNS',

    #
    # Activities
    #
    '/activities/smtp/sessions', 'controllers.iredapd.log.SMTPSessions',
    r'/activities/smtp/sessions/page/(\d+)', 'controllers.iredapd.log.SMTPSessions',
    '/activities/smtp/sessions/(sasl_username|sender|recipient)/(%s)' % e, 'controllers.iredapd.log.SMTPSessionsPerAccount',
    r'/activities/smtp/sessions/(sasl_username|sender|recipient)/(%s)/page/(\d+)' % e, 'controllers.iredapd.log.SMTPSessionsPerAccount',
    '/activities/smtp/sessions/(domain)/(%s)' % d, 'controllers.iredapd.log.SMTPSessionsPerAccount',
    r'/activities/smtp/sessions/(domain)/(%s)/page/(\d+)' % d, 'controllers.iredapd.log.SMTPSessionsPerAccount',
    '/activities/smtp/sessions/(client_address)/(%s)' % ip, 'controllers.iredapd.log.SMTPSessionsPerAccount',
    r'/activities/smtp/sessions/(client_address)/(%s)/page/(\d+)' % ip, 'controllers.iredapd.log.SMTPSessionsPerAccount',
    r'/activities/smtp/sessions/(encryption_protocol)/([0-9a-zA-Z\.]+)', 'controllers.iredapd.log.SMTPSessionsPerAccount',
    r'/activities/smtp/sessions/(encryption_protocol)/([0-9a-zA-Z\.]+)/page/(\d+)', 'controllers.iredapd.log.SMTPSessionsPerAccount',

    '/activities/smtp/sessions/rejected', 'controllers.iredapd.log.SMTPSessionsRejected',
    r'/activities/smtp/sessions/rejected/page/(\d+)', 'controllers.iredapd.log.SMTPSessionsRejected',

    # SMTP Authentications
    '/activities/smtp/sessions/outbound', 'controllers.iredapd.log.SMTPSessionsOutbound',
    r'/activities/smtp/sessions/outbound/page/(\d+)', 'controllers.iredapd.log.SMTPSessionsOutbound',
    '/activities/smtp/sessions/outbound/(sasl_username|sender|recipient)/(%s)' % e, 'controllers.iredapd.log.SMTPSessionsOutboundPerAccount',
    r'/activities/smtp/sessions/outbound/(sasl_username|sender|recipient)/(%s)/page/(\d+)' % e, 'controllers.iredapd.log.SMTPSessionsOutboundPerAccount',
    '/activities/smtp/sessions/outbound/(domain)/(%s)' % d, 'controllers.iredapd.log.SMTPSessionsOutboundPerAccount',
    r'/activities/smtp/sessions/outbound/(domain)/(%s)/page/(\d+)' % d, 'controllers.iredapd.log.SMTPSessionsOutboundPerAccount',
    '/activities/smtp/sessions/outbound/(client_address)/(%s)' % ip, 'controllers.iredapd.log.SMTPSessionsOutboundPerAccount',
    r'/activities/smtp/sessions/outbound/(client_address)/(%s)/page/(\d+)' % ip, 'controllers.iredapd.log.SMTPSessionsOutboundPerAccount',
    r'/activities/smtp/sessions/outbound/(encryption_protocol)/([0-9a-zA-Z\.]+)', 'controllers.iredapd.log.SMTPSessionsOutboundPerAccount',
    r'/activities/smtp/sessions/outbound/(encryption_protocol)/([0-9a-zA-Z\.]+)/page/(\d+)', 'controllers.iredapd.log.SMTPSessionsOutboundPerAccount',

    # API interfaces used by web ui.
    '/api/wblist/senderscore/whitelist/(%s)$' % ip, 'controllers.iredapd.senderscore.WhitelistIPForSenderScore',
    '/api/greylisting/global/whitelist/(%s)$' % ip, 'controllers.iredapd.api_greylist.APIGlobalWhitelist',
]

# API Interfaces
if settings.ENABLE_RESTFUL_API:
    urls += [
        # Throttling
        '/api/throttle/global/(inbound|outbound)', 'controllers.iredapd.api_throttle.APIGlobalThrottle',
        '/api/throttle/(%s)/(inbound|outbound)' % d, 'controllers.iredapd.api_throttle.APIDomainThrottle',
        '/api/throttle/(%s)/(inbound|outbound)' % e, 'controllers.iredapd.api_throttle.APIUserThrottle',

        # Greylisting
        '/api/greylisting/all', 'controllers.iredapd.api_greylist.APIAllSettings',
        '/api/greylisting/global', 'controllers.iredapd.api_greylist.APIGlobalSetting',
        '/api/greylisting/(%s)' % d, 'controllers.iredapd.api_greylist.APIDomainSetting',
        '/api/greylisting/(%s)' % e, 'controllers.iredapd.api_greylist.APIUserSetting',
        '/api/greylisting/global/whitelists', 'controllers.iredapd.api_greylist.APIGlobalWhitelists',
        '/api/greylisting/(%s)/whitelists' % d, 'controllers.iredapd.api_greylist.APIDomainWhitelists',
        '/api/greylisting/(%s)/whitelists' % e, 'controllers.iredapd.api_greylist.APIUserWhitelists',
        '/api/greylisting/whitelist_spf_domains', 'controllers.iredapd.api_greylist.APIWhitelistSPFDomain',
    ]
# fmt: on
