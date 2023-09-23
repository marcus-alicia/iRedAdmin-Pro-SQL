# Author: Zhang Huangbin <zhb@iredmail.org>

# --------------------------------------
# WARNING
# --------------------------------------
# Please place all your custom settings in settings.py to override settings
# listed in this file, so that you can simply copy settings.py while upgrading
# iRedAdmin.
# --------------------------------------

# Debug iRedAdmin: True, False.
DEBUG = False

# Session timeout in seconds. Default is 30 minutes (1800 seconds).
SESSION_TIMEOUT = 1800

# if set to False, session will expire when client ip was changed.
SESSION_IGNORE_CHANGE_IP = False

# Mail detail message of '500 internal server error' to webmaster: True, False.
# If set to True, iredadmin will mail detail error to webmaster when
# it catches 'internal server error' via LOCAL mail server to aid
# in debugging production servers.
MAIL_ERROR_TO_WEBMASTER = False

#
# Logging
#
# Log target: syslog, stdout.
# If set to `syslog`, parameters start with `SYSLOG_` below are required.
LOG_TARGET = "syslog"

# Log level. Used by all logging handlers.
LOG_LEVEL = "info"

#
# Syslog
#
# Syslog server address. Log to local syslog socket by default.
# Syslog socket path:
#   - /dev/log on Linux/OpenBSD
#   - /var/run/log on FreeBSD.
# Some distro running systemd may have incorrect permission on /dev/log, it's
# ok to use alternative syslog socket /run/systemd/journal/syslog instead.
SYSLOG_SERVER = "/dev/log"
SYSLOG_PORT = 514

# Syslog facility
SYSLOG_FACILITY = "local5"

# Log programming error in SQL database, and viewed in `System -> Admin Log`.
# This should be used only in testing server, not on production server, because
# the error message may contain sensitive information.
LOG_PROGRAMMING_ERROR_IN_SQL = False

# Skin/theme. iRedAdmin will use CSS files and HTML templates under
#   - statics/{skin}/
#   - templates/{skin}/
SKIN = "default"

# Set http proxy server address if iRedAdmin cannot access internet
# (iredmail.org) directly.
# Sample:
#   - Without authentication: HTTP_PROXY = "http://192.168.1.1:3128"
#   - With authentication: HTTP_PROXY = "http://user:password@192.168.1.1:3128"
HTTP_PROXY = ""
# Specify hosts which shouldn't be reached via proxy.
# It should be a comma-separated list of hostname suffixes, optionally with
# `:port` appended, for example: `cern.ch,ncsa.uiuc.edu,some.host:8080`.
NO_PROXY = "localhost,127.0.0.1,::1"

# Local timezone. It must be one of below:
#   GMT-12:00
#   GMT-11:00
#   GMT-10:00
#   GMT-09:30
#   GMT-09:00
#   GMT-08:00
#   GMT-07:00
#   GMT-06:00
#   GMT-05:00
#   GMT-04:30
#   GMT-04:00
#   GMT-03:30
#   GMT-03:00
#   GMT-02:00
#   GMT-01:00
#   GMT
#   GMT+01:00
#   GMT+02:00
#   GMT+03:00
#   GMT+03:30
#   GMT+04:00
#   GMT+04:30
#   GMT+05:00
#   GMT+05:30
#   GMT+05:45
#   GMT+06:00
#   GMT+06:30
#   GMT+07:00
#   GMT+08:00
#   GMT+08:45
#   GMT+09:00
#   GMT+09:30
#   GMT+10:00
#   GMT+10:30
#   GMT+11:00
#   GMT+11:30
#   GMT+12:00
#   GMT+12:45
#   GMT+13:00
#   GMT+14:00
LOCAL_TIMEZONE = "GMT"

###################################
# RESTful API
#
# Enable RESTful API
ENABLE_RESTFUL_API = False

# Restrict API access to specified IP addresses or networks.
# if not allowed, client will receive error message 'NOT_AUTHORIZED'
RESTFUL_API_CLIENTS = []

# For standalone admin account.
#
# Hide SQL columns (for SQL editions) or LDAP attributes (for LDAP backends)
# in admin or user profiles.
# If you need to verify admin password, use API endpoint
# '/api/verify_password/admin/<mail>' instead.
API_HIDDEN_ADMIN_PROFILES = ["password", "userPassword"]
API_HIDDEN_USER_PROFILES = ["password", "userPassword"]

###################################
# Domwin ownership verification
#
# Require domain ownership verification if it's added by normal domain admin:
# True, False.
REQUIRE_DOMAIN_OWNERSHIP_VERIFICATION = True

# How long should we remove verified or (inactive) unverified domain ownerships.
#
# iRedAdmin-Pro stores verified ownership in SQL database, if (same) admin
# removed the domain and re-adds it, no verification required.
#
# Usually normal domain admin won't frequently remove and re-add same domain
# name, so it's ok to remove saved ownership after X days.
DOMAIN_OWNERSHIP_EXPIRE_DAYS = 30

# The string prefixed to verify code. Must be shorter than than 60 characters.
DOMAIN_OWNERSHIP_VERIFY_CODE_PREFIX = "iredmail-domain-verification-"

# Timeout (in seconds) while performing each verification.
DOMAIN_OWNERSHIP_VERIFY_TIMEOUT = 10

###################################
# General settings
#
# Show percentage of mailbox quota usage. Require parameter SQL_TBL_USED_QUOTA.
SHOW_USED_QUOTA = True

# SQL table used to store real-time mailbox quota usage.
#   - For SQL backends, it's stored in SQL db 'vmail'.
#   - For LDAP backend, it's stored in SQL db 'iredadmin'.
SQL_TBL_USED_QUOTA = "used_quota"

# Default password scheme, must be a string.
# Passwords of new mail accounts will be encrypted by specified scheme.
#
#   - LDAP backends: BCRYPT, SSHA512, SSHA, PLAIN.
#                    Multiple passwords are supported if you separate schemes
#                    with '+'. For example:
#                    'SSHA+MD5', 'CRAM-MD5+SSHA', 'CRAM-MD5+SSHA+MD5'.
#
#   - SQL backends: BCRYPT, SSHA512, SSHA, MD5, PLAIN-MD5 (without salt), PLAIN.
#                   Multiple passwords are NOT supported.
#
# Recommended schemes in specified order:
#
#   BCRYPT -> SSHA512 -> SSHA.
#
# WARNING: MD5, PLAIN-MD5, PLAIN are not recommended.
#
# Important notes:
#
#   - Password length and complexity are probably more important then a strong
#     crypt algorithm.
#
#   - You can get available algorithms with command `doveadm pw -l`
#     ('BLF-CRYPT' is BCRYPT).
#
#   - BCRYPT: *) must be supported by libc on your system.
#                FreeBSD and OpenBSD support it, but most latest Linux
#                distributions not yet support it.
#                Since Dovecot-2.3.0, BCRYPT is provided by dovecot.
#
#             *) BCRYPT is slower than SSHA512, SSHA, MD5.
#                But, "Speed is exactly what you don't want in a password hash
#                function."
#
#             *) References:
#                - A Future-Adaptable Password Scheme:
#                  http://www.openbsd.org/papers/bcrypt-paper.ps
#                - How to safely store a password:
#                  http://codahale.com/how-to-safely-store-a-password/
#
#   - SSHA512: requires Dovecot-2.0 (or later) and Python-2.5 (or later).
#              If you're running Python-2.4, iRedAdmin will generate SSHA hash
#              instead of SSHA512. But if you're running Dovecot-1.x, user
#              authentication will fail.
#
#              OpenLDAP doesn't support user authentication with SSHA512
#              directly, so you must set 'auth_bind = no' in
#              /etc/dovecot/dovecot-ldap.conf to let Dovecot do the password
#              verification instead.
#
# Sample password format:
#
# - BCRYPT: {CRYPT}$2a$05$TKnXV39M3uJ4o.AbY1HbjeAval9bunHbxd0.6Qn782yKoBjTEBXTe
#           NOTE: Use prefix '{CRYPT}' instead of '{BLF-CRYPT}'.
# - SSHA512: {SSHA512}FxgXDhBVYmTqoboW+ibyyzPv/wGG7y4VJtuHWrx+wfqrs/lIH2Qxn2eA0jygXtBhMvRi7GNFmL++6aAZ0kXpcy1fxag=
# - SSHA: {SSHA}bfxqKqOOKODJw/bGqMo54f9Q/iOvQoftOQrqWA==
# - CRAM-MD5: {CRAM-MD5}465076e1c95ac134fc2ba88ad617b6660958f388d60423504ee7c46ce44be8b4
# - MD5: $1$ozdpg0V0$0fb643pVsPtHVPX8mCZYW/
# - PLAIN-MD5: 900150983cd24fb0d6963f7d28e17f72.
# - PLAIN: Plain text.
#
# References:
#
#   - Dovecot password schemes:
#     https://wiki.dovecot.org/Authentication/PasswordSchemes
#
#
DEFAULT_PASSWORD_SCHEME = "SSHA"

# List of password schemes which should not prefix scheme name in generated hash.
# Currently, only this setting impacts NTLM only.
# Sample setting:
#
#   HASHES_WITHOUT_PREFIXED_PASSWORD_SCHEME = ['NTLM']
#
# Sample password hashes:
#
#   NTLM without prefix: {NTLM}32ED87BDB5FDC5E9CBA88547376818D4
#   NTLM without prefix:       32ED87BDB5FDC5E9CBA88547376818D4
HASHES_WITHOUT_PREFIXED_PASSWORD_SCHEME = ["NTLM"]

# Allow to store password in plain text.
# It will show a HTML checkbox to allow admin to store newly created user
# password or reset password in plain text. If not checked, password
# will be stored as encrypted.
# See DEFAULT_PASSWORD_SCHEME below.
STORE_PASSWORD_IN_PLAIN_TEXT = False

# Always store plain password in additional LDAP attribute of user object, or
# SQL column (in `vmail.mailbox` table).
# Value must be a valid LDAP attribute name of user object, or SQL column name
# in `vmail.mailbox` table.
STORE_PLAIN_PASSWORD_IN_ADDITIONAL_ATTR = ""

# Set password last change date for newly created user. Defaults to True.
# If you want to force end user to change password when first login or send
# first email (with iRedAPD plugin `*_force_change_password`), please set it to
# False.
SET_PASSWORD_CHANGE_DATE_FOR_NEW_USER = True

#
# Password restrictions
#
# Special characters which can be used in password.
# Notes: iOS devices may have problem with character '^'.
PASSWORD_SPECIAL_CHARACTERS = """#$%&*+-,.:;!=<>'"?@[]/(){}_`~"""
# Must contain at least one letter, one uppercase letter, one number, one special character
PASSWORD_HAS_LETTER = True
PASSWORD_HAS_UPPERCASE = True
PASSWORD_HAS_NUMBER = True
PASSWORD_HAS_SPECIAL_CHAR = True

# Log PERMISSION_DENIED operations to stdout or web server log file.
LOG_PERMISSION_DENIED = True

# Redirect to "Domains and Accounts" page instead of Dashboard.
REDIRECT_TO_DOMAIN_LIST_AFTER_LOGIN = False

# List of IP addresses/networks which global admins are allowed to login from.
# Valid formats:
#   - Single IP address: 192.168.1.1
#   - IPv4/IPv6 network: 192.168.1.0/24
GLOBAL_ADMIN_IP_LIST = []

# List of IP addresses/networks which (both global and normal) admins are
# allowed to login from.
# Valid formats:
#   - Single IP address: 192.168.1.1
#   - IPv4/IPv6 network: 192.168.1.0/24
ADMIN_LOGIN_IP_LIST = []

# List all local transports.
LOCAL_TRANSPORTS = [
    "dovecot",
    "lmtp:unix:private/dovecot-lmtp",
    "lmtp:inet:127.0.0.1:24",
]

# Redirect to which page after logged in.
# Available values are: preferences, quarantined, received, wblist, spampolicy.
SELF_SERVICE_DEFAULT_PAGE = "preferences"

###################################
# Maildir related.
#

# It's RECOMMEND for better performance. Samples:
#   - hashed: domain.com/u/s/e/username-2009.09.04.12.05.33/
#   - non-hashed: domain.com/username-2009.09.04.12.05.33/
MAILDIR_HASHED = True

# Prepend domain name in path. Samples:
#   - with domain name: domain.com/username/
#   - without: username/
MAILDIR_PREPEND_DOMAIN = True

# Append timestamp in path. Samples:
#   - with timestamp: domain.com/username-2010.12.20.13.13.33/
#   - without timestamp: domain.com/username/
MAILDIR_APPEND_TIMESTAMP = True

# Mailbox format (in lower cases)
#
# Any mailbox formats supported by Dovecot can be used here, e.g. maildir,
# mdbox. For more details please visit Dovecot website:
# https://wiki.dovecot.org/MailboxFormat
MAILBOX_FORMAT = "maildir"

# Default folder used to store mailbox under per-user HOME directory.
#
#   - Folder name is case SeNsItIvE. Defaults to 'Maildir'.
#
#   - If not set, Dovecot will use the hard-coded setting defined in its config
#     file.
#
#   - It will be appended to the `mail` variable returned by Dovecot SQL/LDAP
#     query. for example, sql query in `/etc/dovecot/dovecot-mysql.conf`:
#
#       user_query = SELECT ...,  CONCAT(...) AS mail, ...
#
#     Or LDAP query in `/etc/dovecot/dovecot-ldap.conf`:
#
#       user_attrs      = ...,=mail=%{ldap:mailboxFormat:maildir}:~/%{ldap:mailboxFolder:Maildir}/,...
MAILBOX_FOLDER = "Maildir"

# How many days the normal domain admin can choose to keep the mailbox after
# account removal.
# To make it simpler, we use 30 days for one month, 365 days for one year.
DAYS_TO_KEEP_REMOVED_MAILBOX = [1, 7, 14, 21, 30, 60, 90, 180, 365]

# How many days the global domain admin can choose to keep the mailbox after
# account removal.
# To make it simpler, we use 30 days for one month, 365 days for one year.
# 0 means keeping forever.
DAYS_TO_KEEP_REMOVED_MAILBOX_FOR_GLOBAL_ADMIN = [
    0,
    1,
    7,
    14,
    21,
    30,
    60,
    90,
    180,
    365,
    730,
    1095,
]

#######################################
# LDAP backends related settings.
#
# Define LDAP server product name: OPENLDAP, LDAPD (OpenBSD built-in ldap daemon)
LDAP_SERVER_PRODUCT_NAME = "OPENLDAP"

# LDAP connection trace level. Must be an integer.
LDAP_CONN_TRACE_LEVEL = 0

# Add full dn of (internal) members to mailing list account.
LDAP_ADD_MEMBER_DN_TO_GROUP = True
LDAP_ATTR_MEMBER = "member"

# Additional LDAP attribute names of user object you want to manage.
# Format:
#
#   {'attribute_name': {'desc': 'A short description of this attribute',
#                       'allowed_domains': [...],
#                       'properties': [...]}}
#    'attribute_name2': {...}}
#
# Arguments
# ----------
#
# desc: string. [optional]
#       a short description of this attribute.
#       If not present, defaults to show attribute name.
#
# allowed_domains: list. [optional]
#       a list of domain names which are allowed to use this attribute.
#       if not present, defaults to allow all domains to use the attribute.
#
# properties: list. [optional]
#       a list of pre-defined property names (string).
#       If not present, defaults to ['string'].
#
# Properties
# ----------
#
# - 'require_global_admin': attribute is only managed by global domain admin.
# - 'multivalue': indicates attribute may contain multiple values.
#           If not present, defaults to single value.
#
# - 'string': indicates attribute value is short text. will be displayed as
#           HTML tag "<input type='text'>".
# - 'text': indicates attribute value is long text. will be displayed as HTML
#           "<textarea>".
#
# Warning: 'string', 'text', 'integer' cannot be used at the same time for same
#          attribute.
#
# Sample settings:
#
#   {'carLicense': {}}      # The minimalist setting, just attribute name.
#
#   {'carLicense': {'desc': 'Car License',
#                   'properties': ['string'],
#                   'allowed_domains': ['example.com', 'test.com']}}
ADDITIONAL_MANAGED_USER_ATTRIBUTES = {}

# Additional LDAP objectClass for NEWLY created mail user.
# Sample value: ['inetOrgPerson', 'pwdPolicy', 'ownCloud']
ADDITIONAL_USER_OBJECTCLASSES = []

# Additional LDAP attribute names and values for NEWLY created mail user.
#
# Format:
#       [(attribute_name, [...]),
#        (attribute_name, [...])]
#
# Several placeholders are available:
#   - %(mail)s: mail address of new user
#   - %(domain)s: domain part of new user mail address
#   - %(username)s: username part of new user mail address
#   - %(cn)s: display name of new user
#   - %(plain_password)s: new user's plain password
#   - %(passwd)s: new user's encrypted password
#   - %(quota)d: mailbox quota
#   - %(sgroups)s: a list of assigned mailing lists
#   - %(storageBaseDirectory)s: path of base storage
#   - %(language)s: default language for web UI
#   - %(recipient_bcc)s: recipient bcc email address
#   - %(sender_bcc)s: sender bcc email address
#   - %(next_uid)d: a server-wide free and unique integer for attr `uidNumber`
#   - %(next_gid)d: a server-wide free and unique integer for attr `gidNumber`
#   - %(shadowLastChange)d: number of days since 1970-01-01, defaults to today.
#   - %(shadowLastChange)d+Xd: number of days since 1970-01-01, plus X days (+Xd).
#
# Sample:
#
#   ADDITIONAL_USER_ATTRIBUTES = [('uidNumber', ['%(next_uid)d']),
#                                 ('gidNumber', ['%(next_gid)d'])]
ADDITIONAL_USER_ATTRIBUTES = []

# Additional enabled/disabled services for newly created accounts.
#
#   - both ADDITIONAL_ENABLED_[XX]_SERVICES, ADDITIONAL_DISABLED_[XX]_SERVICES
#     are manageable in account (user/domain) profile page.
#
#   - ADDITIONAL_ENABLED_<X>_SERVICES will be added for newly created account
#     automatically.
#
#     NOTE: This variable is not used by SQL backends, because all services
#           are enabled by default.
#
#   - ADDITIONAL_DISABLED_<X>_SERVICES will not be added for newly created
#     account, admin must go to account profile page to enable them for certain
#     accounts.
#
# Notes:
#
#   *) for LDAP backends, the service names are assigned to attribute
#      `enabledService`. You're free to use custom words for them, for example,
#      if you want to limit vpn access for certain users, feel free to use
#      `enabledService=vpn` for this purpose.
#
#   *) For SQL backends:
#
#      Available enabled/disabled services are:
#
#        smtp
#        smtpsecured
#        pop3
#        pop3secured
#        imap
#        imapsecured
#        deliver
#        managesieve
#        managesievesecured
#        sogo
#        sogowebmail
#        sogocalendar
#        sogoactivesync
#
#      They're mapped to SQL column name in `vmail.mailbox` table with prefix
#      string 'enable'. e.g. 'smtp' is mapped to 'enablesmtp' column.
#
ADDITIONAL_ENABLED_DOMAIN_SERVICES = []
ADDITIONAL_DISABLED_DOMAIN_SERVICES = []

# Additional services for mail user.
ADDITIONAL_ENABLED_USER_SERVICES = []
ADDITIONAL_DISABLED_USER_SERVICES = []

#######################################
# MySQL/PostgreSQL backends related settings.
#
# Allow to assign per-user alias address under different domains.
USER_ALIAS_CROSS_ALL_DOMAINS = False

# List all global admins while listing per-domain admins.
# URL: https://<server>/iredadmin/admins/<domain>
SHOW_GLOBAL_ADMINS_IN_PER_DOMAIN_ADMIN_LIST = False

###################################
# iRedAPD related settings.
#
# Query insecure outbound session in latest hours.
IREDAPD_QUERY_INSECURE_OUTBOUND_IN_HOURS = 24

###################################
# Amavisd related settings.
#
# If Amavisd is not running on the database server (settings.amavisd_db_host),
# you should specify the amavisd server address here.
AMAVISD_QUARANTINE_HOST = ""

# Remove old SQL records of sent/received mails in Amavisd database.
# NOTE: require cron job with script tools/cleanup_amavisd_db.py.
AMAVISD_REMOVE_MAILLOG_IN_DAYS = 3

# Remove old SQL records of quarantined mails.
# Since quarantined mails may take much disk space, it's better to release
# or remove them as soon as possible.
# NOTE: require cron job with script tools/cleanup_amavisd_db.py.
AMAVISD_REMOVE_QUARANTINED_IN_DAYS = 7

# Prefix text to the subject of spam
AMAVISD_SPAM_SUBJECT_PREFIX = "[SPAM] "

# If set to true, non-local mail domains/users will appear in mail logs and
# 'Top Senders', 'Top Recipients' too.
AMAVISD_SHOW_NON_LOCAL_DOMAINS = False

# Query size limit. Used by tools/cleanup_amavisd_db.py.
#
# If server is busy and Amavisd generates many records in a short time,
# cleanup script will cause table lock while updating sql tables, and this
# may cause other sql connections which operating on `amavisd` database
# hang/timeout. in this case, you'd better set this parameter to a low
# value to release the table lock sooner. e.g. 10.
AMAVISD_CLEANUP_QUERY_SIZE_LIMIT = 100

# Additional Amavisd ban rules.
# iRedMail has 4 builtin ban rules since iRedMail-1.4.1:
#   - ALLOW_MS_OFFICE: Allow all Microsoft Office documents.
#   - ALLOW_MS_WORD: Allow Microsoft Word documents (.doc, .docx).
#   - ALLOW_MS_EXCEL: Allow Microsoft Excel documents (.xls, .xlsx).
#   - ALLOW_MS_PPT: Allow Microsoft PowerPoint documents (.ppt, .pptx).
# You can add your custom ban rules here. Format is:
# {"<rule_name>": "<comment>"}
AMAVISD_BAN_RULES = {}

# Show how many top senders/recipients on Dashboard page.
NUM_TOP_SENDERS = 10
NUM_TOP_RECIPIENTS = 10

# Query statistics for last X hours.
STATISTICS_HOURS = 24

###################################
# iRedAdmin related settings.
#
# Keep iRedAdmin admin log for days.
IREDADMIN_LOG_KEPT_DAYS = 365

#####################################################
# mlmmj and mlmmjadmin RESTful API related settings.
#
# The base url of newsletter subscription/unsubscription/error.
# The full url will be: https://domain.com/<NEWSLETTER_BASE_URL>
# WARNING: it must start with '/'
NEWSLETTER_BASE_URL = "/newsletter"

# How long (in hours) the subscription/unsubscription request will expire.
NEWSLETTER_SUBSCRIPTION_REQUEST_EXPIRE_HOURS = 24
NEWSLETTER_UNSUBSCRIPTION_REQUEST_EXPIRE_HOURS = 24

# How long (in hours) we should keep the subscription requests for simple statistics.
NEWSLETTER_SUBSCRIPTION_REQUEST_KEEP_HOURS = 24

# Base url of mlmmjadmin API. For example: 'http://127.0.0.1:7790/api'
MLMMJADMIN_API_BASE_URL = "http://127.0.0.1:7790/api"

# HTTP header used to store the API AUTH TOKEN.
# Defaults to 'X-MLMMJADMIN-API-AUTH-TOKEN'.
MLMMJADMIN_API_AUTH_HEADER = "X-MLMMJADMIN-API-AUTH-TOKEN"

# Verify SSL cert of mlmmjadmin API
MLMMJADMIN_API_VERIFY_SSL = False

# The transport name defined in Postfix master.cf used to call 'mlmmj-receive'
# program. For example:
#
# mlmmj   unix  -       n       n       -       -       pipe
#    flags=ORhu ...
MLMMJ_MTA_TRANSPORT_NAME = "mlmmj"

############################################################################
# Fail2ban integration.
#
# - Currently only querying banned IP from fail2ban SQL database is supported.
# - We use lower cases for parameter names to keep consistency with the ones
#   in `settings.py`.
fail2ban_enabled = False
fail2ban_db_host = '127.0.0.1'
fail2ban_db_port = '3306'
fail2ban_db_name = 'fail2ban'
fail2ban_db_user = 'fail2ban'
fail2ban_db_password = ''

###################################
# Minor settings. You do not need to change them.
#
# Recipient delimiters. If you have multiple delimiters, please list them all.
RECIPIENT_DELIMITERS = ["+"]

# Show how many items in one page.
PAGE_SIZE_LIMIT = 50

# Smallest uid/gid number which can be assigned to new users/groups.
MIN_UID = 3000
MIN_GID = 3000

# The link to support page on iRedAdmin footer.
URL_SUPPORT = "https://www.iredmail.org/support.html"

# Path to the logo image and favicon.ico.
# Please copy your logo image to 'static/' folder, then put the image file name
# in BRAND_LOGO.  e.g.: 'logo.png' (will load file 'static/logo.png').
BRAND_LOGO = ""
BRAND_FAVICON = ""

# Product name, short description.
BRAND_NAME = "iRedAdmin-Pro"
BRAND_DESC = "iRedMail Admin Panel"

# Path to `sendmail` command
CMD_SENDMAIL = "/usr/sbin/sendmail"

# SMTP server address, port, username, password used to send notification mail.
NOTIFICATION_SMTP_SERVER = "localhost"
NOTIFICATION_SMTP_PORT = 587
NOTIFICATION_SMTP_STARTTLS = True
NOTIFICATION_SMTP_USER = "no-reply@localhost.local"
NOTIFICATION_SMTP_PASSWORD = ""
NOTIFICATION_SMTP_DEBUG_LEVEL = 0

# The short description or full name of this smtp user. e.g. 'No Reply'
NOTIFICATION_SENDER_NAME = "No Reply"

#
# Used in notification emails sent to recipients of quarantined emails.
#
# URL of your iRedAdmin-Pro login page which will be shown in notification
# email, so that user can login to manage quarantined emails.
# Sample: 'https://your_server.com/iredadmin/'
#
# Note: mail domain must have self-service enabled, otherwise normal
#       mail user cannot login to iRedAdmin-Pro for self-service.
NOTIFICATION_URL_SELF_SERVICE = ""

# Subject of notification email. Available placeholders:
#   - %(total)d -- number of quarantined mails in total
NOTIFICATION_QUARANTINE_MAIL_SUBJECT = "[Attention] You have %(total)d emails quarantined and not delivered to mailbox"
