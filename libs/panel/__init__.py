# Events in admin log. Detailed comments of event names are defined in
# templates/default/macros/general.html
LOG_EVENTS = [
    'all',
    'login',
    'user_login',
    'active',
    'disable',
    'create',
    'delete',
    'update',
    'grant',        # Grant user as domain admin
    'revoke',       # Revoke admin privilege
    'backup',
    'delete_mailboxes',
    'update_wblist',
    'iredapd',      # iRedAPD rejection.
    'unban',        # Unban IP address
]
