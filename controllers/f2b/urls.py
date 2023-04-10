# Author: Zhang Huangbin <zhb@iredmail.org>

# fmt: off
urls = [
    '/activities/fail2ban/banned', 'controllers.f2b.log.Banned',
    r'/activities/fail2ban/banned/loglines/(\d+)', 'controllers.f2b.log.MatchedLogLines',

    # Warning: it returns JSON.
    '/activities/fail2ban/unbanip/(.*)', 'controllers.f2b.log.UnbanIP',

    # API interfaces used by web ui.
    '/api/activities/fail2ban/banned/count', 'controllers.f2b.api_log.APIBannedCount',
]
# fmt: on
