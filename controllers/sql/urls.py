# Author: Zhang Huangbin <zhb@iredmail.org>

import settings
from libs.regxes import email as e, domain as d

# fmt: off
urls = [
    # Make url ending with or without '/' going to the same class.
    '/(.*)/', 'controllers.utils.Redirect',

    '/', 'controllers.sql.basic.Login',
    '/login', 'controllers.sql.basic.Login',
    '/logout', 'controllers.sql.basic.Logout',
    '/dashboard', 'controllers.sql.basic.Dashboard',

    # Search.
    '/search', 'controllers.sql.basic.Search',

    # Perform some operations from search page.
    '/action/(user|alias|ml)', 'controllers.sql.basic.OperationsFromSearchPage',

    # Export managed accounts
    '/export/managed_accounts/(%s$)' % e, 'controllers.sql.export.ExportManagedAccounts',
    '/export/statistics/admins', 'controllers.sql.export.ExportAdminStatistics',
    '/export/domain/(%s$)' % d, 'controllers.sql.export.ExportDomainAccounts',

    # Domain related.
    '/domains', 'controllers.sql.domain.List',
    r'/domains/page/(\d+)', 'controllers.sql.domain.List',
    # List disabled accounts.
    '/domains/disabled', 'controllers.sql.domain.ListDisabled',
    r'/domains/disabled/page/(\d+)', 'controllers.sql.domain.ListDisabled',
    # Domain profiles
    '/profile/domain/(general)/(%s$)' % d, 'controllers.sql.domain.Profile',
    '/profile/domain/(aliases)/(%s$)' % d, 'controllers.sql.domain.Profile',
    '/profile/domain/(relay)/(%s$)' % d, 'controllers.sql.domain.Profile',
    '/profile/domain/(backupmx)/(%s$)' % d, 'controllers.sql.domain.Profile',
    '/profile/domain/(bcc)/(%s$)' % d, 'controllers.sql.domain.Profile',
    '/profile/domain/(catchall)/(%s$)' % d, 'controllers.sql.domain.Profile',
    '/profile/domain/(throttle)/(%s$)' % d, 'controllers.sql.domain.Profile',
    '/profile/domain/(greylisting)/(%s$)' % d, 'controllers.sql.domain.Profile',
    '/profile/domain/(wblist)/(%s$)' % d, 'controllers.sql.domain.Profile',
    '/profile/domain/(spampolicy)/(%s$)' % d, 'controllers.sql.domain.Profile',
    '/profile/domain/(advanced)/(%s$)' % d, 'controllers.sql.domain.Profile',
    '/profile/domain/(%s)' % d, 'controllers.sql.domain.Profile',
    '/create/domain', 'controllers.sql.domain.Create',

    # Admin related.
    '/admins', 'controllers.sql.admin.List',
    r'/admins/page/(\d+)', 'controllers.sql.admin.List',
    '/profile/admin/(general)/(%s$)' % e, 'controllers.sql.admin.Profile',
    '/profile/admin/(password)/(%s$)' % e, 'controllers.sql.admin.Profile',
    '/create/admin', 'controllers.sql.admin.Create',

    # Redirect to first mail domain.
    '/create/(user|ml|alias)', 'controllers.sql.utils.CreateDispatcher',

    # User related.
    '/users/(%s$)' % d, 'controllers.sql.user.List',
    r'/users/(%s)/page/(\d+)' % d, 'controllers.sql.user.List',
    # List disabled accounts.
    '/users/(%s)/disabled' % d, 'controllers.sql.user.ListDisabled',
    r'/users/(%s)/disabled/page/(\d+)' % d, 'controllers.sql.user.ListDisabled',
    # List all last logins.
    '/users/(%s)/last_logins' % d, 'controllers.sql.user.AllLastLogins',
    # Create user.
    '/create/user/(%s$)' % d, 'controllers.sql.user.Create',
    # Profile pages.
    '/profile/user/(general)/(%s$)' % e, 'controllers.sql.user.Profile',
    '/profile/user/(forwarding)/(%s$)' % e, 'controllers.sql.user.Profile',
    '/profile/user/(bcc)/(%s$)' % e, 'controllers.sql.user.Profile',
    '/profile/user/(relay)/(%s$)' % e, 'controllers.sql.user.Profile',
    '/profile/user/(aliases)/(%s$)' % e, 'controllers.sql.user.Profile',
    '/profile/user/(wblist)/(%s$)' % e, 'controllers.sql.user.Profile',
    '/profile/user/(spampolicy)/(%s$)' % e, 'controllers.sql.user.Profile',
    '/profile/user/(password)/(%s$)' % e, 'controllers.sql.user.Profile',
    '/profile/user/(throttle)/(%s$)' % e, 'controllers.sql.user.Profile',
    '/profile/user/(greylisting)/(%s$)' % e, 'controllers.sql.user.Profile',
    '/profile/user/(advanced)/(%s$)' % e, 'controllers.sql.user.Profile',
    '/profile/user/(rename)/(%s$)' % e, 'controllers.sql.user.Profile',

    '/apiproxy/user/(%s$)' % e, 'controllers.sql.user.APIProxyUser',
    ####################
    # mlmmj mailing list
    #
    '/create/ml/(%s$)' % d, 'controllers.sql.ml.Create',
    # make it compatible with old (LDAP) mailing list
    '/create/maillist/(%s$)' % d, 'controllers.sql.ml.Create',
    '/mls/(%s$)' % d, 'controllers.sql.ml.List',
    r'/mls/(%s)/page/(\d+)' % d, 'controllers.sql.ml.List',
    '/profile/ml/(general|aliases|owners|members|newsletter)/(%s$)' % e, 'controllers.sql.ml.Profile',
    # Add subscribers
    '/profile/ml/add_subscribers/(%s$)' % e, 'controllers.sql.ml.AddSubscribers',
    # migrate alias account to mlmmj mailing list.
    '/migrate/alias_to_ml/(%s$)' % e, 'controllers.sql.ml.MigrateAliasToML',

    # Alias related.
    '/aliases', 'controllers.sql.alias.List',
    '/aliases/(%s$)' % d, 'controllers.sql.alias.List',
    r'/aliases/(%s)/page/(\d+)' % d, 'controllers.sql.alias.List',
    # List disabled accounts.
    '/aliases/(%s)/disabled' % d, 'controllers.sql.alias.ListDisabled',
    r'/aliases/(%s)/disabled/page/(\d+)' % d, 'controllers.sql.alias.ListDisabled',
    '/profile/alias/(general)/(%s$)' % e, 'controllers.sql.alias.Profile',
    '/profile/alias/(members)/(%s$)' % e, 'controllers.sql.alias.Profile',
    '/profile/alias/(rename)/(%s$)' % e, 'controllers.sql.alias.Profile',
    '/create/alias/(%s$)' % d, 'controllers.sql.alias.Create',

    # User admins
    '/admins/(%s$)' % d, 'controllers.sql.user.Admin',
    r'/admins/(%s)/page/(\d+)' % d, 'controllers.sql.user.Admin',

    #
    # Self-service
    #
    '/preferences', 'controllers.sql.user.Preferences',
    '/preferences/(general)$', 'controllers.sql.user.Preferences',
    '/preferences/(forwarding)$', 'controllers.sql.user.Preferences',
    '/preferences/(password)$', 'controllers.sql.user.Preferences',
    # manage owned or moderated mailing lists
    '/self-service/mls', 'controllers.sql.ml.ManagedMls',
    '/self-service/mls/page/(\d+)', 'controllers.sql.ml.ManagedMls',
    '/self-service/ml/profile/(general|owners|members|newsletter)/(%s$)' % e, 'controllers.sql.ml.ManagedMlProfile',
    '/self-service/ml/profile/add_subscribers/(%s$)' % e, 'controllers.sql.ml.ManagedMlAddSubscribers',
]


# API Interfaces
if settings.ENABLE_RESTFUL_API:
    urls += [
        # API Interfaces
        '/api/login', 'controllers.sql.basic.APILogin',

        #
        # Domain
        #
        '/api/domains', 'controllers.sql.api_domain.APIDomains',
        '/api/domain/(%s$)' % d, 'controllers.sql.api_domain.APIDomain',
        # Delete domain, and keep mailboxes for given days
        r'/api/domain/(%s)/keep_mailbox_days/(\d+)' % d, 'controllers.sql.api_domain.APIDomain',
        '/api/domain/admins/(%s$)' % d, 'controllers.sql.api_domain.APIDomainAdmin',

        # User
        '/api/user/(%s$)' % e, 'controllers.sql.api_user.APIUser',
        # Delete user, and keep mailboxes for given days
        r'/api/user/(%s)/keep_mailbox_days/(\d+)' % e, 'controllers.sql.api_user.APIUser',
        '/api/user/({})/change_email/({}$)'.format(e, e), 'controllers.sql.api_user.APIChangeEmail',
        '/api/users/(%s$)' % d, 'controllers.sql.api_user.APIUsers',

        # Alias
        '/api/alias/(%s$)' % e, 'controllers.sql.api_alias.APIAlias',
        '/api/alias/({})/change_email/({}$)'.format(e, e), 'controllers.sql.api_alias.APIChangeEmail',
        '/api/aliases/(%s$)' % d, 'controllers.sql.api_alias.APIAliases',

        # (mlmmj) mailing list
        '/api/mls/(%s$)' % d, 'controllers.sql.api_ml.APIMLS',
        '/api/ml/(%s$)' % e, 'controllers.sql.api_ml.APIML',

        # Admin
        '/api/admin/(%s$)' % e, 'controllers.sql.api_admin.APIAdmin',

        #
        # Misc
        #
        # Verify account password.
        '/api/verify_password/(user)/(%s$)' % e, 'controllers.sql.api_misc.APIVerifyPassword',
        '/api/verify_password/(admin)/(%s$)' % e, 'controllers.sql.api_misc.APIVerifyPassword',
    ]
# fmt: on
