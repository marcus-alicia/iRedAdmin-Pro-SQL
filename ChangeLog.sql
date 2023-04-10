# 5.3
    + Ship Python module web.py (github.com/webpy/webpy, public domain).
    * RESTful API:
        + Able to reset passwords of all users under same domain.

    * Improvements:
        + New: tools/promote_user_to_global_admin.py, used to promote an
          existing mail user to be a global admin.
        - New config parameter: SET_PASSWORD_CHANGE_DATE_FOR_NEW_USER.
          Set password last change date for newly created user. Defaults to True.
          If you want to force end user to change password when first login or
          send first email (with iRedAPD plugin `*_force_change_password`),
          please set it to False.

    * Fixed issues:
        - Can not delete user if email address ends with a whitespace.
        - Domain admin can still login when domain is disabled.
          Thanks Linh Phan for the feedback.
        - tools/upgrade_iredadmin.sh: incorrect uwsgi path on CentOS 8.
        - tools/reset_user_password.py: Not set password last change date when
          reset user password.

    + Translations:
        - New: Swedish (sv_SE).
          Thanks Anders Johansson <johansson _at_ aljmedia.se>.

# 5.2
    * Improvements:
        - Return server-side-render text for new mailing list subscription API.
        - Add link to mailing list profile page in "Top Senders" section on
          Dashboard page.
        - Support custom email notification template file on server deployed
          with iRedMail Easy platform:
          `/opt/iredmail/custom/iredadmin/notify_quarantined_recipients.html`

    * Fixed issues:
        - Normal admin can view all admin's activities.
        - Default uwsgi buffer size (4096) for iRedAdmin may be too small if
          iRedAdmin is running behind a proxy server. Increased to 8192 now.
          Thanks Marcel for the feedback.
        - Can not list disabled domains.
          Thanks Linh Phan for the report.
        - Programming error while accessing newsletter subscription page.

# 5.1
    * Improvements:
        - tools/import_users.py now supports employee id.

    * Fixed issues:
        - Removing domain should not remove all email forwarding destinations
          which are users under the removed domain.
          Thanks to Anzulo1984@GitHub for the report.
        - Disallow non-ascii characters in email username and domain name.
        - Not support email address with IP address as domain name. For
          example, `user@[192.168.1.1]`.

# 5.0
    * Fixed issues:
        - RESTful API: Updating user profile causes empty value of SQL column
          `mailbox.mailboxfolder`.
        - Self-service: missing pagination on moderated mailing lists page.
        - Settings stored in SQL db does not work in command line tools.
        - Domain admin was able to set unlimit mailbox quota for user even
          there's a domain-level mailbox quota.
        - Error displaying banned rules if it's empty.
          Thanks to laiyukwa@GitHub for the report.
        - Invalid function argument while calling API to create new user.
          Thanks to Dmitriy Maksimov for the report.
        - Can not set per-user and per-domain banned rules.
          Thanks to Peter Schumacher for the report.
        - Not correctly display number of banned IP addresses on Dashboard page.
        - Not disable web browser autocomplete feature for input fields like
          username and passwords while creating new account.
        - Not correctly detect new version and display a button to request
          download link.

    * Updated translations.
        + Danish (da_DK). Thanks Søren Mortensen <sm _at_ upnavigator.dk>.

= 4.9 =
    * Improvements:
        - Able to enable or disable per-user SOGo webmail, calendar and
          activesync service.
        - Allow to assign Amavisd ban rules to user, domain or globally.
          FYI: https://docs.iredmail.org/iredadmin-pro.custom.ban.rules.html
        - Able to view all users' last login dates, including imap/pop3 login,
          and latest delivered message.
        - Add link to system settings in "About mail logs" modal.

    * Fixed issues:
        - Can not correct display time stamp in "Sent/Received Emails" page.
        - It now allows omit mailbox folder name while creating new user.
        - Admin can not update (subscribeable) mailing list owners and
          moderators.

= 4.8 =
    * Improvements:
        + (base64) Decode log lines stored by Fail2ban.
        + Able to limit max recipients of single message.
          Note: iRedAPD-5.0 is required.
        + Standalone admin account now has timezone setting.
        + Self-service: able to manage owned or moderated mailing lists,
          including updating profile, members, newsletter-style subscription.
          Thanks to Konrad Oleksinski for the sponsorship.
        + Able to log to stdout. Thanks to tms0@GitHub.
        + Activities are logged to SQL db by default, it now logs to
          syslog/stdout too.

    * Fixed issues:
        - Not update moderator and owner of mailing list while changing user's
          email address.
        - Not reject emails before queue if user is marked as not to accept
          emails.
        - tools/cleanup_amavisd_db.py: Not correctly remove old records.
        - tools/import_users.py: can not import users correctly with Python 3.

    * Updated translations.
        + Spanish (es_ES). Thanks Gonzalo Meneses (alakentu@github).

= 4.7 =
    * Fixed issues:
        - No menu item to visit rejected smtp sessions.
        - Error while searching mail accounts.
        - Not keep pagination on rejected smtp sessions page.
        - Error (in some cases) while sending notification emails to recipients
          of quarantined messages.
        - Error while viewing quarantined mails.
        - Error while exporting per-domain accounts.
        - Error while whitelisting IP for senderscore service.
        - Error while converting timestamp to local timezone.
        - Error while sending notification to recipient of quarantined mails.

= 4.6 =
    * Improvements:
        - Able to search mailing list account.

    * Fixed issues:
        - Error while deleting all admin activitys (`Activites -> Admin Log`).
        - Can not view quarantined mail message.
        - Error while searching mail accounts.
        - Can not view user profile if domain has mulitple mail alias accounts.
        - Several errors in upgrade script `tools/upgrade_iredadmin.sh`.

= 4.5 =
    * Improvements:
        - Python-3.5 or later is required. Python-2 support has been dropped completely.

    * Fixed issues:
        - Cannot always successfully start `iredadmin` service on FreeBSD.
        - Can not get count of banned IP addresses in some case.
        - Not validate whitelist addresses for greylisting service.
        - Not remove non-existing addresses in same domain while updating
          per-domain catch-all addresses.
        - Can not set relay without verifying local recipients.
        - Fix few functions which takes no keyword arguments.
        - Not validate existence of local email address(es) while updating
          per-user BCC addresses.
        - Not keep pagination after performed action on user list page.
        - `Top Senders` on Dashboard page doesn't work.

    * Updated translations.
        - Japanese (ja_JP). Thanks Osakana Taro (osakanataro@github).
        - Danish (da_DK). Thanks Søren Mortensen <sm _at_ upnavigator.dk>.

= 4.4 =
    * RESTful API:
        + Able to whitelist IP for senderscore checking (applied by iRedAPD
          plugin `senderscore`) on `SMTP sessions` page.
          - URL: `PUT /api/wblist/senderscore/whitelist/<ip>`
        + Able to whitelist IP for greylisting service (applied by iRedAPD
          plugin `greylisting`) on `SMTP sessions` page.
          - URL: `PUT /api/greylisting/global/whitelist/<ip>`

    * Improvements:
        - Display max user quota besides the "Default quota of new user" input
          field for normal admin.
        - Able to view log lines which triggered the ban by Fail2ban.
        - Able to view reverse DNS name of banned IP address.
        - Able to specify hours of statistics data on Dashboard page with
          parameter `STATISTICS_HOURS`, defaults to `24` hours.
        - Create connection to iRedAPD database only once.
        - Able to verify CRYPT-SHA-512 password hash (handled by 'doveadm pw').

    * Fixed issues:
        - Incorrect time zone for Turkey/Istanbul, it's now GMT+03:00.
        - The sender of subscription confirmation was hard-coded to
          `no-reply@localhost.local`, it's now set to mailing list itself.
        - SMTP session time is not rendered with correct time zone.
        - If either parameter `amavisd_enable_logging` or
          `amavisd_enable_quarantine` is set to False, daily cron job
          `tools/cleanup_amavisd_db.py` will not run.

= 4.3 =
    * Improvements:
        - Able to unban IP addresses.

            Note: If your server was deployed with iRedMail Easy platform,
            this should be enabled by default. If deployed with the
            downloadable iRedMail installer, please follow our tutorial to
            configure Fail2ban to store banned IP in SQL database:
            https://docs.iredmail.org/fail2ban.sql.html

        - Able to manage alias addresses for mailing list account.
        - Failed login will be logged to syslog.
        - It now display last login time of both IMAP and POP3 logins.

    * Fixed issues:
        - Not disable access to per-user or per-domain (Sent/Received Mails)
          activity pages if admin is disallowed to view the activities.

    * Updated translations.
        - New: Latvian (lv_LV). Thanks Juris BALANDIS (JurisBALANDIS@GitHub).
        - Triditional Chinese (zh_TW). Thanks WildfootW@GitHub.
        - Simplified Chinese (zh_CN).

= 4.2 =
    * RESTful API:
        - Fixed: resetting mail forwarding (with `forwarding=`) generates
          incorrect SQL record.

    * Improvements:
        - Allow to mark domain as backup mx without specifying primary mx
          (Postfix will query DNS record to get primary mx).
        - Normal admin can not set min/max password lengths shorter/longer than
          global settings.
        - Able to disallow normal admin to manage min/max password lengths.
        - Able to view banned IP addresses (in Fail2ban).
          Note: This is available only when you setup iRedMail server with
          iRedMail Easy platform.

    * Fixed issues:
        - Not store password last change date while updating user password
          via RESTful API.
        - Not correctly remove user profiles while iRedAPD and Amavisd are
          disabled.
        - Modified incorrect settings while updating admin profile.

= 4.1.2 =
    * Fixed issues:
        - Can not save mail forwarding addresses.
        - Incorrect pagination on smtp outbound session history page.
        - Incorrect pagination on disabled mail alias account list page.

= 4.1.1 =
    * Fixed issues:
        - Can not save a copy of forwarded messages.
          Thanks Mark (mark _at_ bluebanana.com) for the feedback.

= 4.1 =
    * RESTful API:
        - Able to add new or remove existing mail forwarding addresses.
          - URL: `PUT /api/user/<mail>`
          - Parameter names: `addForwarding`, `removeForwarding`

    * Improvements:
        - Disallow few characters in local accounts' email addresses: +, =, /.
        - Simplify uwsgi log format.

    * Fixed issues:
        - Incorrect syslog id in uwsgi config file.
        - Log of outbound session with sasl_username filter doesn't work.
        - Incorrect pagination on smtp session history page.

= 4.0 =
    * Improvements:
        - Display number of smtp authentications and rejected smtp sessions
          on Dashboard page. NOTE: This feature requires iRedAPD-3.2.
        - Display detailed logs of smtp authentication and rejected smtp
          sessions. NOTE: This feature requires iRedAPD-3.2.

    * Fixed issues:
        - Not correctly convert mail alias account to subscribeable mailing list.
        - Can not whitelist/blacklist top-level domain name like `.com` as
          reverse DNS domain name.
        - Can not correctly count in/out emails.

= 3.9 =
    * Fixed issues:
        - Do not display menu `System -> Settings` for normal admin.
          Thanks Eckehardt Riedel <e.riedel _at_ webserv-it dot de> for the
          feedback.
        - Pagenation on mailing lists page doesn't work.
        - Per-domain password length is not applied.
        - Admin log page doesn't work in some cases.
        - tools/upgrade_iredadmin.sh: not set correct syslog socket on FreeBSD.

= 3.8 =
    * Fixed issues:
        - Not correctly update spam policy to quarantine detected virus.
        - Not ignore white/blacklists which contain non-ascii chars.
        - Not display password last change date with correct time zone.

= 3.7 =
    * Improvements:
        - tools/bulk_import.py: able to disable https SSL cert verification.

    * Fixed issues:
        - Can not filter existing email addresses due to a programming error.
          Thanks to sfletcher for the report in forum.


= 3.6 =
    * RESTful API:
        - Able to manage global, per-domain and per-user whitelists and
          blacklists.
        - Fixed: Not check whether mail alias account exists before updating
          profile.
          Thanks David Good <dgood _at_ willingminds.com> for the report.

    * Improvements:
        - iRedAdmin-Pro now logs error message to syslog, facility "local5".
        - Able to verify SHA512-CRYPT password hash with `doveadm pw` command.

    * Fixed issues:
        - Can not save mail alias members with extension (e.g.
          user+folder@domain.com).
        - If user is disabled, newly added forwarding addresses were not disabled.
        - Activating a disabled mail alias account doesn't activate its members.
          Thanks Susan for the report and firming video to help reproduce the
          issue.
        - Can not delete mail alias account on search result page.
          Thanks marius.timukas for the report in forum.
        - Not correctly enable disabled user.

    * Misc:
        - File renamed: tools/bulk_import.py -> tools/import_users.py.

= 3.5 =
    * RESTful API:
        - Able to create mail user with a password hash instead of plain
          password (parameter name `password_hash`).
        - Fixed: can not update max message size of subscribeable mailing list.
        - Fixed: can not update per-user services.
          Thanks Christopher Dent <chris _at_ grolis.com> for the report.

    * Improvements:
        + Display user last login date on search result page.
          Note: it requires additional setup by following this tutorial:
          https://docs.iredmail.org/track.user.last.login.html

    * Fixed issues:
        - Not correctly redirect to mailing list profile page on `System ->
          Received Mails` page.
        - Can not save outbound throttle setting in some cases.
        - Improper tooltip text for viewing/editing domain profile on domain
          list page.
        - Not correctly get first character of account email addresses.
        - Not convert values of global settings returned by SQL query to
          correct formats.
        - Do not log error message if python module netifaces is not available.
        - Do not log error message for PostgreSQL backend if no sql table
          `vmail.last_login`.
        - tools/cleanup_amavisd_db.py: not establish proper SQL connection.
        - tools/update_mailbox_quota.py: not read quota size correctly.
        - tools/bulk_import.py: read mail user accounts from text file and
          import them with the RESTful API interface.

= 3.4 =
    * RESTful API:
        * Always return user last login date.
          URIs:
            - `GET /api/user/<mail>`
            - `GET /api/users/<domain>`

    * Improvements:
        + Correctly show first character of existing mail addresses on
          user/maillist/alias account list page.
        + Display user last login date on user list page and profile page.
          Note: This requires Dovecot config change, please follow our
          tutorial here: https://docs.iredmail.org/track.user.last.login.html

        + Store and manage few iRedAdmin-Pro settings in SQL db.
          Updating iRedAdmin-Pro config file `settings.py` still works, but
          settings in SQL db have higher priority.

        + tools/export_last_login.py: used to export user last login time.
          Note: You need to follow this tutorial to enable last_login plugin in
          Dovecot: https://docs.iredmail.org/track.user.last.login.html

    * Fixed issues:
        - Not display the saved value for disabling account creating in
          domain profile page.
        - Can not get first character of username/domain with PostgreSQL 8.x
          on CentOS 6.
          Thanks Stanislav Studený <studeny _at_ vut.cz> for the report and fix.
        - Can not limit number of mailing lists while creating mail domain.
        - It counts virus email which is not quarantined in SQL db.

= 3.3 =
    * RESTful API:
        * Able to update account status of mail alias account.
          URI: `PUT /api/alias/<mail>`, parameter `accountStatus`
        * Able to update per-user sender/recipient bcc.
          URI: `PUT /api/user/<mail>`
        * Able to get all users' and aliases' profiles of given domain.
          URI: `GET /api/users/<domain>`
          URI: `GET /api/aliases/<domain>`

    * Improvements:
        + Able to sort mail users by display name.

    * Fixed issues:
        - tools/delete_mailboxes.py:
            - (python) syntax error when removes mailboxes without timestamp
              in maildir path.

= 3.2 =
    * Fixed issues:
        - Not correctly remove user from subscribed mailing list while
          removing mail user.
        - Can not filter admin activity log.
        - Not correct detect allowed IP for global admins.
          Thanks Ralph Hensel <ralph.hensel _at_ convar.com> for the report in
          iRedMail Easy platform.
        - Can not delete all quarantined emails in database.
        - Not remove user from subscribed mailing lists while removing user.
        - Can not request download link of new iRedAdmin-Pro release.
        - tools/delete_mailboxes.py: not verify whether the maildir of removed
          user contains other user's mailbox.

    * Translations:
        - Updated: German (de_DE).
          Thanks Martin Hofheinz <info _at_ netzwerk-design _dot_ net>.
          Thanks toxicvengeance @ github.
          Thanks lug-gh @ github.

= 3.1 =
    * Fixed issues:
        - Incorrectly show featured relevant to Amavisd on domain profile page
          when it's not installed.
        - Not correctly parse quarantined email message.
        - Upgrade script 'tools/upgrade_iredadmin.sh' doesn't correct restart
          web service.

    * Translations:
        - Updated: German (de_DE).
          Thanks Martin Hofheinz <info _at_ netzwerk-design _dot_ net>.

= 3.0 =
    * RESTful API:
        * Able to add subscribers while creating (subscribeable) mailing list.
        * Able to add/remove subscribers while updating (subscribeable) mailing
          list.
        * Able to get all subscribers of given mailing list with optional
          parameter `with_subscribers=yes`:
            - URI: `GET /api/ml/<mail>?with_subscribers=yes`
        * Able to list all mailing lists in given domain:
            - URI: `GET /api/mls/<domain>`
            - Optional parameters:
                - `email_only=yes`: if present, return a list of mailing list
                  email addresses. Otherwise return a list of mailing list
                  profiles.
        * Able to set mailbox format, mailbox folder name, full maildir path
          while creating/updating user:
          - URLS:
            - `POST /api/user/<mail>`
            - `PUT  /api/user/<mail>`
            - Parameters: `mailboxFormat`, `mailboxFolder`, `maildir`.
        * Show mailbox size and number of stored messages while getting user
          profile:
            - URI: GET /api/user/<mail>
            - New parameter names: stored_bytes, stored_messages.
        * Show assigned mail alias groups and mailing lists while getting user
          profile:
            - URI: GET /api/user/<mail>
            - New parameter names: mailing_aliases, mailing_lists.
        * Able to reset user password by submitting a password hash
          (`PUT /api/user/<mail>`, parameter `password_hash`).
        * Fixed issues:
            - Cannot verify password: `POST /api/verify_password/user/<mail>`.
            - Not correctly set date to deleted mailboxes while deleting a
              domain (`DELETE /api/domain/<domain>/keep_mailbox_days/<number>`)
              Thanks Wes Cossick <wes _at_ hoa-express.com> for the report.

    * Improvements:
        + Able to export statistics of admins.
        + If new password doesn't match policies, display error messages of
          all unmatched policies.
        + Spam policy: able to set score for blocking/quarantining detected
          spam.
        + On search result page, now able to set days to keep mailbox of
          removed domain and user accounts.
        + Able to define days to keep removed mailbox for normal domain admin
          and global admin.

          With default settings, normal admin can keep mailbox for 1 day,
          1/2/3 weeks, 1/2/3/6/12 months.

          Global admin can keep mailbox for 1 day, 1/2/3 weeks, 1/2/3/6/12
          months, 2/3 years, and 'forever'.

        + Display user password last change date on user list page and user
          profile page.
        + Able to set mailbox format while creating new user.
        + New: tools/dump_quarantined_mails.py, used to dump quarantined
          emails to the directory given on command line. It's useful if you
          want to train SpamAssassin by calling `sa-learn`.

    * Fixed issues:
        - While deleting a domain, it removes all forwarding destinations
          addresses under this domain, but it should be kept for those
          forwarding source addresses which don't belong to removed domain.
        - When login as normal admin, it lists global admins in the per-domain
          admin list page.
        - Normal domain admin should not be able to update max user quota.
        - Cannot correctly sort domain names on domain list page.
        - Cannot unassign user from external mail aliases on user profile page.
        - Cannot filter admin log.
        - Cannot set throttle setting to inherit from lower priority account.
        - Not strip leading and ending spaces in search string.
        - Incorrectly delete assigned external mail alias groups while updating
          mail user profile.
        - Cannot disable imap service per user.
        - Not correctly set spam policy to deliver detected
          spam/virus/badheader/banned mail to mailbox while quarantining is
          disabled.
        - Not delete all emails of selected quarantined type (e.g. spam,
          virus). It deleted all emails no matter which quarantined type you
          are viewing.
        - Not handle service name 'pop3tls' and 'imaptls' for Dovecot-2.3.
        - Not use AMAVISD_QUARANTINE_HOST as mlmmj relay host if a remote
          Amavisd server is used.
        - tools/notify_quarantined_recipients.py:
            - Cannot generate email message if quarantined mail subject
              contains non-ascii characters.
            - Not correctly handle mail subject in some case.

    * Translations:
        - New: Danish (da_DK). Thanks Søren Mortensen <sm _at_ upnavigator.dk>.
        - Updated: German (de_DE). Thanks lug-gh on github.

= 2.9.0 =
    * RESTful API:
        * Show allocated domain quota while getting domain profile
          (`GET /api/domain/<domain>`).
        * Able to manage alias domains while updating domain profile
          (`GET /api/domain/<domain>`):
            * `aliasDomains`: reset all alias domains
            * `addAliasDomain`: add new alias domains
            * `removeAliasDomain`: remove existing alias domains
        * Parameter names changed while updating domain profile
          (`PUT /api/domain/<domain>`):
            * `enableService` was renamed to `addService`
            * `disableService` was renamed to `removeService`
            * `removeAllServices` was renamed to `services`

    * Improvements:
        - mlmmj mailing list integration. Mailing list is now subscribable via
          email or web.

          Admin can migrate existing mail alias account to subscribable mailing
          list in account profile page, all profiles (members/moderators,
          access policy, etc) will be fully migrated.

        - Able to export all managed accounts with one click.
        - Able to disable domain ownership verification per admin for newly
          created domain.
        - Able to disable normal domain admin to view mail log and manage
          quarantined mails.

    * Fixed issues:
        - Not correctly set spam policy while no options were updated.
        - self-service: user cannot update white/blacklists while removing
          log of received/sent mails.
          Thanks Jochen Häberle <jochen _at_ haeberle _dot_ net> for the
          feedback in forum.
        - Not delete records which use removed mail accounts as destination bcc
          address.
        - Not display stored messages and size in user profile page if user has
          unlimited mailbox quota.
        - Cannot set user mailbox quota to unlimited by leaving the input field
          empty.
        - Cannot correctly indicate managed domains in user profile page.
          Thanks Slawomir Wrobel <slawek _at_ studio-it.pl> for the report.
        - Filter on domain list page shows only first letter of all existing
          domains instead of hard-coded letters.
        - Dead link used to display greylisting tracking data.
        - Per-user bcc settings were removed while updating per-domain bcc
          settings.
        - Email address with extension is considered as not existing.
        - Not correctly display indicator of mail forwarding in search result
          page.
          Thanks Luke6283 <support _at_ sbcjolley.com> for the report in forum.
        - Not correct set spam policy if `Quarantine spam` is not checked in
          spam policy setting page.
          Thanks Jorge <jorge _at_ bsd.com.br> for the report in forum.
        - Normal admin cannot edit user mailbox quota.
          Thanks Adil Demiri <adil _at_ sgn.net> for the report.
        - tools/notify_quarantined_recipients.py: Cannot get correct timestamp
          of quarantined emails.
        - tools/cleanup_amavisd_db.py: endless loop in some case with
          PostgreSQL.

    * Translations:
        - Update German (de_DE). Thanks Peter <info _at_ nuw.biz>.
        - Update Italian (it_IT). Thanks Francesco <frankonet _at_ infinito.it>.

= 2.8.0 =
    * RESTful API:
        + NEW: Able to list all managed domains (/domains).
        + NEW: Able to manage per-usre enabled mail services (/user/<mail>).
        + NEW: Able to promote mail user to be a global admin (/user/<mail>).
        + Enhancement: Return managed domain names while getting user (must
          have admin privilege) or admin profile.

    * Improvements:
        - Able to filter domains in the "Managed Domains" section on user/admin
          profile page.

    * Fixed issues:
        - RESTful API:
            - It always requires password while updating domain admin profile.

        - Cannot view domain list and domain profile with MariaDB-10.x.
          Thanks Torkil Liseth <torkil.liseth _at_ gmail.com> for the feedback.
        - Not delete records in `forwardings` table while removing mail alias
          account.
          Thanks lamagra <slawek _at_ studio-it.pl> for the report in forum.

          To delete dead / orphan mail alias accounts, please run SQL commands:

            USE vmail;
            DELETE FROM forwardings WHERE is_list=1 AND address NOT IN (SELECT address FROM alias);

        - Cannot update per-domain bcc if there's alias domain.
        - Not return 'INVALID_CREDENTIALS' if login with a not-existing domain
          name.
        - If login as normal domain admin, search result will return matched
          accounts not in managed domain.
        - If a mail user is marked as domain admin with privilege to mark other
          user as admin, it's able to assign user to any domain hosted on
          server.
        - Cannot use '*@domain.com' as alias moderator.
        - Cannot save wildcard sender addresses for whitelist/blacklists.
        - Top 10 Senders/Recipients show non-local users.
        - Not correctly paginate domain list.
        - Cannot store maildir path of removed user due to incorrect variable
          type.
        - Not use current date as password last change date for created user.
        - Cannot update per-domain throttle settings.

= 2.7.0 =
    * RESTful API:
        + NEW: Able to manage global, per-domain and per-user greylisting
          settings, whitelist senders, and global whitelisted SPF domains.

    * Improvements:
        - While removing mail user account, option 'Keep (mailbox) forever'
          now log a null delete date instead of keeping for 100 years.
          Thanks mejo <jonas _at_ freesources.org> for the feedback in forum.
        - Able to manage whitelists/blacklists based on reverse DNS name of
          sender server IP address.
          Sponsored development by Daniel Senie <dts _at_ amaranth.com>.
        - Able to search accounts based on per-user alias address and mail
          forwarding address.
        - Display per-user alias addresses and mail forwarding addresses in
          search result page.
        - Able to define custom favicon.ico with parameter BRAND_FAVICON.
        - Able to use CIDR network as whitelist/blacklists. e.g.
          192.168.1.0/24, 2002::1234:abcd:ffff:c0a8:101/64.
          Sponsored development by Daniel Senie <dts _at_ amaranth.com>.
        - Able to generate and verify SHA512 password hash.
        + New: tools/reset_user_password.py, used to reset user password.

    * Fixed issues:
        - RESTful API:
            - Not remove admin privilege after revoked domain admin privilege
              if admin doesn't manage any domain anymore.
            - Not correctly set per-domain enabled/disabled domain profiles.
            - Cannot get per-domain sender dependent relayhost while getting
              domain profile.
            - Cannot correctly remove per-domain sender/recipient BCC settings.
            - Cannot correctly reset per-domain transport if domain was marked
              as backup MX.
            - Not correctly update profiles (password, global admin privilege)
              for standalone admin account.
            - Cannot set per-user alias addresses while creating new mail user.
            - Cannot add or remove per-user alias addresses while updating user
              profile.
            - User mailbox quota was removed while updating user profile.
              Thanks Dorian Gutowski <dorian _at_ 604media.com> for the report.
            - Not use default transport setting while creating new domain.
        - Cannot remove user from assigned groups in user profile page.
        - Not delete managed domains if user (which has admin privilege) after
          revoked admin privilege.
        - Not store plain password while user changing password -- if
          iRedAdmin-Pro is configured to store plain password.
          Thanks Sergio <sergio _at_ winc.net> for the report.
        - Not remove per-account wblist/greylisting/throttle settings and
          tracking data while removing account.
        - Not correctly count accounts while listing accounts with first letter
          of email address.
        - Not correctly page if current account list page is filtered with
          first letter of email address.
        - Not remove throttle and greylisting settings while removing domains.
        - Spam policy (quarantining) doesn't fully working.
        - If user is assigned as moderator of mail alias account, after user
          was removed, it still exists in alias moderator list.
        - Not use custom settings while getting top sender/recipients on
          Dashboard page.
          Thanks nicolasfo <nicolas _at_ franceoxygene.fr> for the report.
        - Not update backupmx status while disabling 'Relay without verifying
          local recipients' in domain profile page, tab 'Relay'.
          Thanks Luftar Braha <luftar.braha _at_ gmail> for the report.
        - tools/notify_quarantined_recipients.py:
            - Not convert time to local time zone.
              Thanks roy.wong <roy.wong _at_ jmi.com.hk> for the report.

= 2.6.0 =
    * Fixed issues:
        - API:
            - Cannot save a (email) copy while updating per-user mail forwarding.
              Thanks Wes Cossick <wes _at_ hoa-express.com> for the report.
        - Not correctly enable alias domain after domain ownership
          verification.
        - Should not require domain ownership verification if alias domain was
          added by global admin.
        - Not disable white/blacklisting actions in 'Quarantined Mails' page
          if white/blacklist is disabled by domain admin in user preferences.
          Thanks Rain <rain6966@gmail> for the report.
        - Cannot create new mail user due to miss sql column name in 'GROUP BY'
          statement.
        + tools/notify_quarantined_recipients.py:
            - unicode error if mail subject contains unicode characters.
            - unicode error if system default encoding is 'ascii'
          Thanks Rain <rain6966@gmail> for the report.
        - tools/upgrade_iredadmin.sh cannot create new MySQL table due to
          missing required privilege.

= 2.5.0 =
    * APIs:
        * Several parameter names have been changed for simplification:
            + old: `cn` -> new: `name`
            + old: `mailQuota` -> new: `quota`
            + old: `preferredLanguage` -> new: `language`
        * Variable names used in returned JSON data have been changed to avoid
          possible namespace conflict:
            + old: {'success': ...,  'msg': ...}
            + new: {'_success': ..., '_msg': ...}
        + NEW: /api/users/<domain>: Update profiles for all users under domain.
        + NEW: /api/users/<domain>/password: Update all user passwords under domain.
        + NEW: /api/domain/admins/<domain>: manage domain admins.
        + NEW: Verify given (plain) password against the one stored in LDAP.
            - /api/verify_password/user/<mail>
            - /api/verify_password/admin/<mail>
        + NEW: /api/admin/<mail>: manage standalone domain admins.
        + Able to delete mail domain or user with option to keep mailboxes for
          given days.
        + Able to update more domain profiles (/api/domain/<domain>):
            + default mailbox quota for new user.
            + max mailbox quota of newly created mail user
            + catch-all account
            + inbound and outbound relay
            + sender bcc, recipient bcc
            + set max number of users, aliases, mailing lists
            + disabled domain profiles
            + disabled user profiles
            + disabled user preferences
        + Able to update more user profiles (/api/user/<mail>):
            + mail forwarding
            + employee id
            + per-user alias addresses
        + Able to change email address of user/alias accounts.
        + Able to set members while creating mail alias account.
        + Able to update members while updating mail alias account.
        + Able to get profile of existing mail domain/user/alias.
        + NEW: Able to manage global, per-domain and per-user spam policy.
        - Fixed: Cannot set per-domain quota while creating domain.

    * Improvements:
        + Normal domain admin is now able to create new mail domains with
          limits like number of max domains/users/alias/lists/quota.

          Note: new mail domain added by normal domain admin requires domain
          ownership verification. For more details, please check our tutorial:
          http://www.iredmail.org/docs/iredadmin-pro.domain.ownership.verification.html

        + Able to use domain name as primary MX server (IP address is
          recommended).
        + Able to enable/disable pop3/imap/smtp/sogo/managesieve services for
          existing or newly created mail users under domain in domain profile
          page.
        + Able to enable/explicitly disable greylisting for domain/user.
        + Able to schedule date to delete mailboxes while removing domain or
          mail users.

          Note: This feature requires a daily cron job to run
          `tools/delete_mailboxes.py`.

        + Able to set access policy while creating mail alias account.
        + Able to set timezone while creating mail domain.
        + New: tools/update_password_with_csv.py, used to reset password by
          reading password from CSV file (format: '<email> <password>').
        + tools/dump_disclaimer.py: able to dump disclaimer for alias domains.
        + tools/cleanup_amavisd_db.py: Huge performance improvement with dirty
          read (SELECT) while cleaning up old records in Amavisd database.
        + tools/notify_quarantined_recipients.py:
            + able to track last notify time and notify for new quarantined
              emails only.
            + able to notify users under backup MX domains with command line
              argument '--notify-backupmx'.
            + correctly encode mail subject and sender name

    * Fixed issues:
        - SECURITY: iRedAdmin accepts any password on FreeBSD and OpenBSD
          if password is stored in BCRYPT hash.
        - Standalone admin account cannot change its own password.
        - Standalone admin account can be an email address under locally
          hosted mail domain. This causes conflict when there's a normal mail
          user with same email address.
        - Normal domain admin cannot view/update its own profile if it doesn't
          manage its own domain.
        - Not check current email address existence while changing account
          email address.
        - Not update sql column `mailbox.local_part` while changing account
          email address.
        - Not remove per-user alias addresses while removing user account.
        - Cannot use domain name as Primary MX in backup mx setting page.
        - Cannot delete mail user account due to incorrect PostgreSQL command.
        - Cannot use non-ascii characters in mail subject and body of
          notification mail used to notify local recipient of quarantined mails.
        - Cannot search mail accounts with PostgreSQL backend.
        - Normal domain admin can view or update global domain admin's profile.
        - Cannot save submitted greylisting whitelists while there's a
          duplicate sender inserted by `tools/spf_to_greylist_whitelists.py`.
          Thanks Juan Bou Riquer <jbou _at_ cancun.com.mx> for the report.
        - Incorrect pages while viewing disabled accounts.
          Thanks to Li Wei <liwei _at_ bond520.com> for the report.
        - Incorrectly count number of mail alias accounts in domain list page.
          Thanks to Santosh Gupta <head.it _at_ satmatechnologies.com> for the
          report.
        - Separated normail domain admin cannot change its own password.
        - Able to set unlimited mailbox quota when per-domain quota was set.
        - Cannot handle mail alias members if some character is
          in uppercase.
        - Not specify path to python command to run 'tools/cleanup_db.py' in
          upgrade script, this causes error in cron job.
        - Incorrectly update domain backupmx status while updating profile
          under tab 'General'.
        - iOS devices may have problem with character '^' in password. we
          remove it from allowed special character for randomly generated
          password.
        - Creating domain in invalid domain format causes 'internal server error'.
        - Fix the html target="_blank" vulnerability.

    * Translations:
        - Update Traditional Chinese (zh_TW). Thanks rain <rain6966@gmail>.
        - Update Simplified Chinese (zh_CN).

= 2.4.0 =
    * RESTful API. Read document below for more details:
      http://www.iredmail.org/docs/iredadmin-pro.restful.api.html

    * Improvements:
        + Able to set limits of mail user/alias accounts while creating new
          domain.
        + Able to search user alias address (name and email address).
        + Able to manage per-domain and per-user sender dependent relayhost.
        + Able to enable/disable SOGo service for a single user in user
          profile page.
        + Bring back option 'Relay without verifying local recipients' for
          per-domain relay setting.
        + Show progress bar in domain list page to indicate percentage of used
          quota (and allocated quota).
        + Show a small icon as indicator:
            - on domain list page: indicate certain domain has alias domain(s).
            - on user list page: indicate current account has alias and
              forwarding addresses.
          Moving cursor on the icon will show more details like
          alias/forwarding addresses.

    * Fixed issues:
        - Not remove email address which contains invalid character while
          updating alias members/moderators.
        - Cannot convert invalid date/time to local time.
        - Not add required header (Content-Type: text/html) for web pages.
        - Not correctly handle submitted alias moderators.
        - tools/cleanup_amavisd_db.py: Not correctly delete unreferred sql
          records in Amavisd database, this bug may incorrectly delete some
          whitelists/blacklists.
        - Cannot correctly sort mail users by used quota of mailbox with
          PostgreSQL backend.
          Thanks Andris Vasers <andris.vasers _at_ rigasvilni.lv> for the report.
        - Updating per-domain and per-user greylisting setting will delete
          greylisting whitelisted domains.

    * Updated translations:
        + Spain (es_ES).
          Thanks Juan Bou Riquer <jbou@cancun.com.mx>.

= 2.3.1 =
    * Fixed issues:
        + Not correctly strip email addresses which contains delimiter.

= 2.3.0 =
    * Completely remove support for Policyd and Cluebringer.
      iRedMail shipped Policyd in very early releases, THANK YOU. GOODBYE.
    * tools/wblist_admin.py has been removed, it's available in iRedAPD-1.8.0.

    * Improvements:
        + Able to manage greylisting whitelist domains.
        + New option of 'Disabled self-service preferences' in domain profile
          page, under tab 'Advanced': View basic info of received mails.
        + Better spam policy control: able to control bypassing or
          quarantining detected spam/virus/banned/bad-header email.

    * Fixed issues:
        - Cannot release quarantined email on some Linux distributions.
        - Cannot add email address like 'user+ext@domain.com' as alias member.
        - Improper maildir path if username contains more than 3 characters.
          Thanks bardzotrudny <bardzotrudnymail _at_ gmail> for the report in
          forum.
        - Cannot update throttle settings.
          Thanks ketan.aagja <ketan.aagja _at_ gmail> for the report in forum.
        - Self-service is not working.
        - Not correctly set greylisting priorities.
          Thanks Animatrix <kurt6459 _at_ gmail> for the report in forum.
        - Incorrect regular expressions of email address and domain name, cause
          several '404 page not found' errors, and cannot access user profile
          page whose email address contains a dot like 'abc.def@domain.com'.

    * Updated translations:
        + Spain (es_ES).
          Thanks Juan Bou Riquer <jbou@cancun.com.mx>.
        + Bulgarian (bg_BG).
          Thanks Пламен Василев <p.vasileff _at_ gmail.com>.

= 2.2.0 =
    NOTE: Greylisting and throttling offered by iRedAPD conflict with
          Policyd/Cluebringer, so if you want to use Policyd/Cluebringer,
          please disable iRedAPD integration in config file `settings.py` with
          setting `iredapd_enabled = False`.

          We have greylisting and throttling support in iRedAPD as replacement,
          and here's tutorial to help you migrate from Cluebringer to iRedAPD:
          http://www.iredmail.org/docs/cluebringer.to.iredapd.html

    * Improvements:
        - Able to restrict user to login from specified IP addresses or network.
          (under user profile page, tab "Advanced".)
        - Able to manage global, per-domain and per-user greylisting and
          throttle settings implemented with iRedAPD.
        - Able to list disabled domain/user/mailing list/alias accounts.
        - Allow to store mail user's plain password in additional column in
          `vmail.mailbox` table.
        - Able to bypass bad-header checking in spam policy setting page.
        - Able to manage per-user alias addresses.
        - Show iRedMail version number stored in /etc/iredmail-release.
        - Able to manage white/blacklists for outbound message.
        - tools/cleanup_amavisd_db.py won't cause lock issue or performance
          issue anymore.
        - New scripts:
            + tools/update_mailbox_quota.py: update mailbox quota for one user
              (specified on command line) or bulk users (read from a plain text
              file).

    * Fixed issues:
        + Not correctly update spam subject text (spam_subject_tag3).
          Thanks rafaelr <rafaelr _at_ icctek.com> for the report in forum.
        + Cannot correctly handle improper unicode string in mail headers
          while viewing quarantined mail.
        + Not correctly submit per-domain white/blacklists while submitting
          from 'Quarantined Mails' page as normal domain admin.
        + Cannot set empty time zone and preferred language.
        + Not generate proper maildir path when first 3 characters in
          username part of email address contains dot.
        - Cannot verify BCRYPT password hash with '{BLF-CRYPT}' prefix.
        - Not correctly set access restriction to account profile page.
        - Not correctly set domain as backup mx.

    * Updated translations:
        + Germany (de_DE).
          Thanks Joachim Buthe <buthe _at_ gugw.tu-darmstadt.de> and
          Martin Hofheiz <m.hofheinz _at_ netzwerk-design.net>.
        + Spain (es_ES).
          Thanks informatica _at_ ttu.es.
        + Simplified Chinese (zh_CN).

= 2.1.3 =
    * Improvements:
        - Command line tool to manage white/blacklists: tools/wblist_admin.py.
          Supported operations: add/delete/list whitelists or blacklists for
          server-wide, per-domain, per-user. Run the script without any
          arguments to get a help message.
          Note: tools/submit_wblist.py was removed.

    * Fixed issues:
        - Not correctly assign default mail group(s) to newly created mail user.
          Thanks <alex.ab.travel _at_ gmail.com> for the report.

= 2.1.2 =
    * Fixed issues:
        - Not correctly update `alias` table while changing user's mail address.
        - Cannot delete user in search page.
          Thanks Grzegorz Leśkiewicz <mstgeo _at_ yes.pl> for the report.

    * Updated translations:
        + Germany (de_DE).
          Thanks Joachim Buthe <buthe _at_ gugw.tu-darmstadt.de>.
        + Spain (es_ES).
          Thanks informatica _at_ ttu.es.

= 2.1.1 =
    * Fixed issues:
        - Normal admin cannot update alias profile.
          Thanks Hilario Ortigosa Monteoliva <hortigosa _at_ octanio.es> for
          the feedback.

= 2.1 =
    * Improvements:
        - Able to white/blacklist senders or recipients in System -> Mail Logs
          -> Sent Mails (or Received Mails).

    * Fixed issues:
        - Improperly checking per-admin time zone for separate admin account.
        - Cannot set mail forwarding in self-service page.
        - Incorrect function arguments when calling simple_profile() defined
          in libs/sqllib/user.py.
        - Always set per-user preferred language to system default value.
        - Cannot delete/enable/disable mail alias account.
        - Incorrect variable name in controllers/panel/log.py causes
          'internal server error' while accessing Admin Log page.

= 2.0 =
    Note: iRedAdmin-Pro-MySQL is now merged into iRedAdmin-Pro-SQL.

    * Improvements:
        - Able to set per-domain and per-user time zone.
        - Allow to specify amavisd server address if amavisd and sql database
          are not running on the same host.
        - Able to filter out accounts by first character in email address or
          domain name.
        - Self-service is now a per-domain setting, not more global setting.
          Global admin can enable/disable self-service in domain profile page,
          under tab 'Advanced'.
        - New script: tools/notify_quarantined_recipients.py. Used to query
          quarantined mails and notify local recipients (via email) they
          have emails quarantined on server and not delivered to their
          mailbox.
          It's ok to setup a cron job to run this script every, for example,
          6 or 12 hours, it's up to you.
        - Able to white/blacklist senders on Quarantined Mails page.
        - Able to change email address of mail user/alias account in place.
        - Log profile update operations.
        - Show per-user mailbox quota in self-service preference page.
        - Pulling out plain text of HTML email while displaying quarantined
          email. NOTE: this feature requires Python module BeautifulSoup.
        - New script: tools/submit_wblist.py, used to submit white/blacklist
          from command line. Sample usage:
          python tools/submit_wblist.py --blacklist 192.168.1.10 user@test.com
        - Able to use 'user@*' as white/blacklist sender.

    * Fixed issues:
        - Cannot disable global throttling.
        - Cannot correctly redirect to page of certain type of quarantined
          mails after release/delete emails.
        - Not verify members in same domain while updating user forwarding.
        - Cannot list IPv6 address(es) assigned on network interface(s) on
          Dashboard page.
        - Cannot blacklist top-level domain name (e.g. @.com).
        - Cannot delete alias account.


= 1.9.2 =
    * Improvements:
        - Log message after updated mail list members/moderators.
        - Able to use '*@domain.com' as moderator of mail alias account.
          Note: this requires iRedAPD-1.4.5.
        - New script tool: migrate_cluebringer_wblist_to_amavisd.py.
          Used to migrate Cluebringer white/blacklists to Amavisd database.

          Note: Don't forget to enable iRedAPD plugin `amavisd_wblist` in
          /opt/iredapd/settings.py.

    * Fixed issues:
        - Cannot delete mail alias account.
        - Cannot display all domains in user profile page.
        - Not wrap subject/sender/recipient in Sent/Received Mails page.
        - Cannot correctly delete all Sent/Received mails in SQL database.
        - Not correctly handle SQL column `policy.spam_subject_tag3` while
          updating spam policy. This column doesn't exist in Amavisd-new-2.6.x.
        - Cannot remove existing white/blacklists.
        - Upgrading script (tools/upgrade_iredadmin.sh) should restart uwsgi
          sesrvice instead of nginx if Nginx is running as web server.
        - Not save 'Always insert X-Spam-* headers' setting in 'Global Spam
          Policy' page.
        - Show improper links in self-service spam policy page.
        - 'INNER JOIN' in tools/cleanup_amavisd_db.py causes performance
          issue while removing old records in amavisd database.

    * Updated translations:
        + Spain (es_ES).
          Thanks informatica _at_ ttu.es.

= 1.9.1 =
    * Fixed issues:
        - Not handle msg 'WBLIST_UPDATED' in self-service page.
        - Not correctly save per-user wblist in self-service page.
        - Remove existing wblist after adding new ones.
        - Raise 'internal server error' if login username/password is wrong.
        - Cannot delete all quarantined mails.

= 1.9.0 =
    * New features:
        - Better Amavisd integration:

          o Able to set max size of single incoming email.
            Note: it requires iRedAPD plugin `amavisd_message_size_limit`.

          o Able to manage per-domain, per-user white/blacklists, and it's
            integrated with Amavisd.

              + Although this white/blacklists works with Amavisd after-queue,
                but you'd better enable iRedAPD plugin `amavisd_wblist` to
                reject blacklisted senders during smtp session to save system
                resource.

              + It replaces white/blacklists provided by Cluebringer, but
                Cluebringer wblist also works.

            o Able to set global, per-domain and per-user (basic) spam policy.

        - self-service. Normal user can login to manage their own profile
          (name, password), forwarding, per-user white/blacklist, quarantined
          mails, and check received mails.

          o Self-service is disabled by default. Please set below parameter
            in iRedAdmin config file 'settings.py' then reload/restart Apache
            web service or uwsgi service if you're running Nginx.

            ENABLE_SELF_SERVICE = True

          o Domain admin can restrict allowed self-service preferences in
            domain profile page, under tab 'Advanced'.

          o Server admin is able to set which self-service page should be
            displayed after user login. Sample setting in iRedAdmin config
            file:

              SELF_SERVICE_DEFAULT_PAGE = 'preferences'  # Default setting
              SELF_SERVICE_DEFAULT_PAGE = 'quarantined'  # Quarantined Mails
              SELF_SERVICE_DEFAULT_PAGE = 'received'     # Received Mails

          o User is able to white/blacklist sender or sender domain in
            'Quarantined Mails' page.

          o User is able to blacklist sender or sender domain in
            'Received Mails' page.

    * Improvements:
        + Able to sort quarantined mails by spam score.
        + Able to generate 'CRAM-MD5' password hash with command `doveadm pw`.
        + Able to generate bcrypt password hash with Python module 'bcrypt' or
          'py-bcrypt'.

          It works on BSD systems, but not Linux. Since libc shipped in most
          Linux distributions doesn't support bcrypt, Dovecot cannot verify
          bcrypt hash on Linux.

        + Able to sort mail users by mailbox quota usage percentage.
        + Able to restrict IP addresses where global admin are allowed to login
          from (new setting parameter: GLOBAL_ADMIN_IP_LIST).
        + Show spam score in quarantined page and received mail log page.
        + Able to filter quarantined emails by quarantined type: bad header.
        + Able to set default per-user sender/recipient bcc address for newly
          created mail user.

    * Fixed issues:
        - Not escape random password in account creation page. this bug causes
          iRedAdmin displays an incomplete password.
        - Cannot set domain quota to unlimited with radio checkbox.
          Thanks Dinis D <dueldanov _at_ gmail> for the report.
        - Incorrect regular expression which not support IDN domain name.
        - Cannot white/blacklist some IP addresses due to incorrect regular
          expression.
        - Not correctly show domain status (active/inactive) in domain list
          page when domain is inactive but has custom relay.
        - Not sync 'mailbox.enablelda' and 'mailbox.enablelmtp' while updating
          'mailbox.enabledeliver'.
        - Not show `mailbox.employeeid` in search result.
        - Not correctly mark user as normal admin or global admin.
        - Use removed SQL columns while searching accounts.
        - Cannot set per-user mailbox quota.
          Thanks Kim Gardner <ferrisxb9r _at_ gmail.com> for the report.
        - Generated random password is longer than max password length.
          Thanks labasus <labas _at_ gmx dot co.uk> for the report.
        - Not detect openSUSE in script tools/upgrade_iredadmin.sh.
        - Duplicate value of 'Received' header while rendering quarantined mail
          headers.

    * Updated translations:
        + Spain (es_ES).
          Thanks informatica _at_ ttu.es.
        + Portuguese (Brazil), (pt_BR).
          Thanks Douglas Medeiros <douglasmedeiros@tic.ufrj.br>.

= 1.8.2 =
    * Improvements:
        + New script used to help upgrade iRedAdmin open source edition or
          old version of iRedAdmin-Pro.
        + Able to filter quarantined emails by quarantined type: clean.
        + Enhanced password restrictions. New password must has at least
            - one letter
            - one uppercase letter
            - one digit number
            - one special characters
        + Set default time (15 mintues) of inactivity before session expires.
        + Normal admin is now able to manage multiple domains, and mark other
          mail user as domain admin.
        + Able to add record of sub-domain for Cluebringer whitelist/blacklist.

    * Fixed issues:
        + Not render pages in selected language in drop-down list in Login page
          after logged in.
        + Not delete global admin record in `vmail.domain_admins` while
          deleting mail domain.
          Thanks sergiocesar <sergio _at_ winc dot net> for the report.
        + Not allow to use longer top domain name in regular expression used to
          verify domain name and email address.
        + Incorrect URL handle in Amavisd quarantined mail list.
          Thanks Adrian Schurr <Adrian.Schurr _at_ siag.ch> for the report.
        + Incorrectly paged list of quarantined mails.
          Thanks Michael <michaelchong2005 _at_ gmail> and Kyle Harris
          <kyle _at_ theharrishome.com> for the report.
        + Not verify permission while searching mail log.
          Thanks Khanb <balajikhan13 _at_ gmail> for the report.
        + Incorrect function name in libs/policyd/greylist.py.
          Thanks <mail _at_ mensmaximus.de> for the report.

= 1.8.1 =
    * Fixed issues:
        + Cannot detect or switch to language on login page.
          Thanks Robert <robert-kuehn _at_ gmx.de> for the report.
        + Not correctly count number of in/out mails.
          Thanks Robert <robert-kuehn _at_ gmx.de> for the report.
        + Not correctly disable Policyd/Cluebringer status.
          Thanks spango <spango _at_ ecentral.com> for the report.

= 1.8.0 =
    * Cluebringer support:
        + Server-wide, per-domain and per-user inbound/outbound throttling.
          NOTE: Throttling does NOT apply to emails sent from internal
          domains to internal domains.
        + Add domain as internal domains while creating new mail domain.
        + Remove domain from internal domains while removing mail domain.
        + Greylisting:
            o Able to enable/disable per-domain and per-user greylisting.
            o Able to list/remove accounts which has greylisting disabled.
            o Able to update basic greylisting settings for 'Default Inbound'.
        + White/Blacklist:
            o View, add, delete white/blacklist records.

    * Improvements:
        + Detect non-ascii character in password and raise error message.
          Thanks Chris <chris _at_ chrispyfur.net> for the feedback in forum.
        + Able to filter quarantined emails by quarantined type: spam, virus,
          banned.
        + Switch config file from ini format to Python source file, this makes
          programming and upgrading easier.

    * Fixed:
        + Mail user which marked as global admin but not domain admin cannot
          create new mail user/alias account.
          Thanks Hugo Ferreira <hferreira _at_ pontoc.pt> for the report.
        + Mail user which marked as global admin but not domain admin cannot
          view Sent/Received mail log.
          Thanks Hugo Ferreira <hferreira _at_ pontoc.pt> for the report.
        + Normal admin cannot search quarantined mail log.
          Thanks Hugo Ferreira <hferreira _at_ pontoc.pt> for the report.
        + Explicitly tell Amavisd to release quarantined mail stored in SQL
          database with addition release command 'quar_type=Q'.
          Thanks cts.cobra _at_ gmail for the report and help in our forum.
        + Not delete SQL record in 'vmail.domain_admins' while removing
          mail user which is domain admin.
          Thanks Atendimento GrupoW <atendimento _at_ grupow.com.br> for the
          report.
        + Not return correct allocated quota size while creating new user
          for newly created domain.
          Thanks Simon Kulessa <kulessa _at_ mediaproject.de> for the report.
        + Use HTTP_PROXY defined in settings.py first, if empty try proxy
          server defined in environment variable 'http_proxy'.
          Thanks Bernhard Roth <broth _at_ roth-itk.de> for the report and
          propose.
        + Not correctly get number of per-admin managed alias accounts while
          logging in as normal admin.
          Thanks Bryan and Neil in NetEasy Inc. for the report.

    * New or updated translations:
        + Russia (ru_RU). Thanks Андрей Бережков <kidhtc _at_ gmail>.

= 1.7.0 =
    * New features:
        + Log maildir path of deleted mail domain or user in table
          'vmail.deleted_mailboxes'. Maildir path is concatenate with 3 columns:
          CONCAT(storagebasedirectory, '/', storagenode, '/', maildir).
        + Global admin can set per-domain disabled domain/user profiles in
          domain profile page. Normal admin cannot view and update disabled
          profiles.

    * Improvements:
        + Mark/Unmark users as domain admin or global admin in user list page.
        + List internal domain admins in separate page: /admins/[domain].
        + Redirect from admin profile page (/profile/admin/general/xx) to user
          profile page (/profile/user/general/xxx) if admin is a mail user.
        + Able to delete admin accounts from Admins page (/admins) if admin
          is a mail user.
        + Link to account profile page for account name in search page.
        + Able to set addition settings in domain creation page:
          domain quota, default quota/language for new user.
        + Set per-domain default language for newly created mail users.

    * Fixed:
        + Not list mail admin which are mail user in "System -> Admin Log".
        + Not show correct used mailbox quota in domain list page.
          Thanks Ivo Schindler <ivo.schindler _at_ i-web.ch> for the report.
        + Cannot limit user mailbox quota in user profile page.
        + Searching full email address returns empty result.
          Thanks our forum user "tonyd" <tonydema _at_ gmail> for the report.
        + Not check new version of iRedAdmin-Pro.
        + Cannot show top 10 recipients in Dashboard page.
          Thanks melaleuca5 <info _at_ divertido.ca> for the report in forum.

    * New or updated translations:
        + Korean (ko_KR). Thanks Bosung Lee <gotocloud _at_ gotocloud.co.kr>

= 1.6.0 =
    * Improvements:
        + Show content type (spam/virus/banned) of quarantined mails.
        + Able to set relay without verifying local recipients.
        + New password schemes: SSHA, SSHA512.
          Note: SSHA512 requires Dovecot-2.0 (and later), Python-2.5 (or
          later).
        + Show breadcrumb links in account creation pages.
        + Don't show duplicate tabs in Users/Lists/Aliases list pages.

    * Fixed:
        - Can use primary domain as alias domain.
        - Script tools/cleanup_amavisd_db.py cannot read local settings in
          libs/settings_local.py.
          Thanks Bruce MacKay <bmackay _at_ razyr.net> for the report.
        - Not update greylisting opt-in/out for alias domains.
          Thanks gleenj <glenn _at_ neondigital.com> for the report.
        - Not update account status in `alias` table while updating account
          status of mail user.
          Thanks Mickey Everts <mickey.everts _at_ otcorp.com> for the report.
        - Script tools/cleanup_amavisd_db.py cannot delete older SQL records
          in Amavisd database.
          Thanks broth <broth _at_ roth-itk.de> for the report in forum.
        - Cannot store default domain transport setting if user submits empty
          value in domain profile (relay) page.
        - Not assign new user to default mail groups.
          Thanks Matteo Fracassetti <info _at_ drgiorgini.it> for the report.
        - Not show number of existing alias accounts in domain profile.
          Thanks thatday <win3c _at_ 126.com> for the report.
        - Not update domain/user bcc records while adding/removing alias domains.
        - Not update mailbox.enablesieve, mailbox.enablesievesecured correctly.
          Thanks thatday <win3c _at_ 126.com> for the report.
        - Incorrectly unset domainGlobalAdmin status in session after updating
          admin profile.
          Thanks Tue <tt _at_ atorbital.com> and escu <cosmin.necula@gmail> for
          the report.

    * New or updated translations:
        + Traditional Chinese (zh_TW). Thanks Ho ho <ho.iredmail _at_ gmail.com>.
        + Polish (pl_PL). Thanks Adrian Grygier <adi _at_ zwami.pl>.
        + Spain (es_ES). Thanks Luis Armando Perez Marin.
        + Russian (ru_RU). Thanks Taylor D <hoper.me _at_ gmail.com>.
        + Serbian (Cyrillic, sr_CS). Thanks Robert Bogdan <rbogdan _at_ color.rs>.
        + Slovenian (sl_SI). Thanks Marko Kobal <marko.kobal _at_ arctur.si>.
        + French (fr_FR). Thanks Shafeek Sumser <shafeeks _at_ gmail.com>.
        + Portuguese (Brazilian, pt_BR). Thanks Wendell Martins Borges <perlporter
          _at_ gmail.com>.
        + Finnish (fi_FI). Thanks Teemu Harjula <teemu.harjula _at_ tietovirta.fi>.
        + Itilian (it_IT). Thanks Nicolas Cauchie <nicolas _at_
          franceoxygene.fr>, Riccardo Raggi <riccardo _at_ raggi.eu>, and Alberto
          Baudacci <a.baudacci _at_ me.com>.
        + Netherlands (nl_NL). Thanks Luc Verhoeven <lverhoeven _at_ vcn.nl>
        + German (de_DE). Thanks Ivo Schindler <ivo.schindler _at_ i-web.ch>,
          and Martin <info _at_ netzwerk-design.net>.
        + Czech (cs_CZ). Thanks Roman Pudil <roman _at_ webhosting.fm>.

= 1.5.1 =
    * Fixed:
        + List normal users in Admins page.

    * New and updated translations:
        + Update German translation (de_DE). Thanks "Sascha Wolski | cognitics
          GmbH" <wolski _at_ cognitics.de>.
        + Update Brazilian (pt_BR).
          Thanks "Julio C. Oliveira" <julioc _at_ paranet.com.br>.

= 1.5.0 =
    * New features:
        + Mark domain as backup MX.
        + New cron script: tools/cleanup_amavisd_db.py.
          Used to remove old records of incoming/outgoing/quarantined mails.
        + Mark mail user as admin of its domain and/or global admin.

    * Improvements:
        + Cron script tools/dump_disclaimer.py was rewritten, no need to
          edit it anymore, just specify the directory used to store disclaimer
          file. e.g. python tools/dump_disclaimer.py /etc/postfix/disclaimer/.
        + Allow to redirect to domain list page instead of Dashboard page
          after login: REDIRECT_TO_DOMAIN_LIST_AFTER_LOGIN (libs/settings.py).
        + Show search box on top-right corner.
        + Show more domain status in domain list page: relay, backupmx.
        + Add some sample relay settings as reference.
        + Set http proxy server address in libs/settings.py (HTTP_PROXY)
          if iRedAdmin cannot access internet (iredmail.org) directly.
          Thanks Bernhard Roth <broth _at_ roth-itk.de> for helping test.
        + Oops, don't allow normal domain admin to manage both per-domain and
          per-user throttling.

    * Fixed:
        + Cannot delete all per-user activities with one-click.
          Thanks melaleuca5 <info _at_ divertido.ca> for the report.
        + Incorrect real-time quota in user list page with unlimited quota.
          Thanks HV <jan _at_ volesak.com> for the report.
        + Didn't remove SQL records of real-time mailbox quota while deleting
          mail domain or user.
        + Cannot delete all records of received mails with one-click.
        + Not convert timestamp of admin logs to LOCAL_TIMEZONE.

    * New and updated translations:
        + Update Brazilian (pt_BR). Thanks "Julio C. Oliveira"
          <julioc _at_ paranet.com.br>.
        + Czech (cs_CZ). Thanks Roman Pudil <roman _at_ webhosting.fm>.

= 1.4.0 =
    * Improvements:
        + Show basic license info.
        + Allow to use plain MD5 password.
        + Manage quarantined banned emails.
        + Per-domain and per-user greylisting control in account profile
          page, under tab Advanced.
        + Show search string in search result page.
        + Verify email address for per-domain bcc settings if mail domain is
          a local domain.
        + Allow normal domain admin to manage both per-domain and per-user
          throttling.

    * Fixed:
        + Add missed msg handlers in account list pages.
          Thanks Jure Pečar <jure.pecar _at_ arctur.si> for the report.
        + Cannot delete all quarantined mails with one click.
        + Cannot perform search.
        + Get realtime mailbox quota from incorrect SQL table.
          Thanks Edgaras Dagilis <e.dagilis@lku> for the report and fix.
        + Cannot handle timezones with minutes. e.g. GMT+5:45.

    * New and updated translations:
        + Slovenian (sl_SI). Thanks Marko Kobal <marko.kobal _at_ arctur.si>.
        + Polish (pl_PL). Thanks Adrian (adi _at_ zwami.pl)

= 1.3.1 =
    * Improvements:
        + Able to search mail domains.
        + Read used mailbox quota from separate table 'used_quota'.
        + Save password last change date in column: mailbox.passwordlastchange.
        + Able to set global timezone in libs/settings.py: LOCAL_TIMEZONE.
        + Allow to store user password in plain text in libs/settings.py:
          STORE_PASSWORD_IN_PLAIN.
          Thanks brothner <bryan.orthner@kcdc.ca>.

    * Fixed:
        + Show quarantined emails of all domains instead of specified domain.
          Thanks mmh@forum for the report.
        + Not completely delete user related records while removing user from
          search result page.
          Thanks wangning_wang@staff.easou.com for the report.
        + Cannot assign alias as member of another alias account.

    * New and updated translations:
        + Polish (pl_PL). Thanks Krzysztof Skurzyński <k.skurzynski@kospel.pl>.
        + Finnish (fi_FI). Thanks Teemu Harjula <teemu.harjula@tietovirta.fi>.

= 1.3.0 =
    * New features:
        + Sender and recipient throttling, available as per-user and per-domain
          settings.

    * Improvements:
        + Show used quota percentage in user profile page. Thanks atros <christian@eol.co.nz>.
        + Assign user to aliases in user profile page.
        + Remove deleted user from mail aliases (member).
        + Delete all sent/received logs with one-click.
        + Better SQL performance while listing all domains.
          Thanks atros <christian@eol.co.nz>.

    * Fixed:
        + Cannot delete some records of sent/received mail log. Caused by
          incorrect mail_id, secret_id character set.
          Thanks Michael <zhongjh@jamestextile.com>.
        + Typo error in alias member list. Thanks John Hannawin <john@i-next.co.uk>.
        + Not allow '+' in email address. Thanks <wayneliao38@gmail>.

    * New and updated translations:
        + Brazilian Portuguese (pt_BR). Thanks Fabricio Caseiro <fcaseiro@tic.ufrj.br>.
        + Itilian (it_IT). Thanks Alberto <alberto@graphite.eu>.
        + Russian (ru_RU). Thanks Dmitry Sukharev <suds77@gmail.com>.
        + German (de_DE). Thanks info@netzwerk-design.net <info@netzwerk-design.net>.
        + Traditional Chinese (zh_TW). Thanks Wayne <wayneliao38@gmail.com>.
        + Spanish (es_ES). Thanks Lucas <lucas@landm.net>.

= 1.2.1 =
    * Fixed:
        + Cannot delete quarantined VIRUS mails when try to delete all
          quarantined mails with one click. Thanks beez <jason@indo.net.id>.
        + Cannot list per-domain and per-user activities.
          Thanks Chris Ip <chris.ip@efaith.com.hk>.
        + Incorrect count of Sent, Received mails with normal admin.
          Thanks Chris Ip <chris.ip@efaith.com.hk>.

= 1.2.0 =
    * Improvements:
        + CSRF protect.
        + Able to delete all admin logs with one click.

    * Fixed:
        + Cannot view quarantined VIRUS mails. Thanks beez@forum
          <jason@indo.net.id>.
        + Incorrect links of pages in per-user and per-domain activity list.
        + Allow to use domain names which end with 2-6 chars.
          Thanks Julian P. <@consistency.at>.
        + Fix EXCEEDED_DOMAIN_ACCOUNT_LIMIT issue while creating new user.
          Thanks Emidio Reggiani <emidio.reggiani@...it>, Tecnologia - PLUGNET
          <tecno@plugnet.com.br>
        + Allow normal admin to update catch-all address of domain.
          Thanks Chris Ip (chris.ip@...hk).
        + Some possible XSS, XSRF vulnerabilities.

= 1.1.0 =
    * New features:
        - Search log of sent/received/quarantined mails based on domain name
          or email address.
        - Able to view per-user and per-domain sent/received/quarantined mail
          logs.
        - Able to set mail deliver restriction for mail alias, add moderators.
          Note: This feature requires iRedAPD-1.3.4 or later.
        - Able to disable for creating mail user/list/alias.
        - Store passwords in plain text.

    * Improvements:
        - Separate bcc/relay tab in user profile page.
        - Generate a random password while setting/resetting password.
        - Show spam level (score) in quarantined page.
        - Able to delete all quarantined mails with one click.
        - Show mail size in received/sent mail logs.
        - Sortable sent/received/quarantined mail log pages.
        - Delete old amavisd records only once in each login session.
        - Better unicode handle in quarantined/sent/received mail logs.
        - Show admin type (global/normal) in admin list page.
        - Delete alias from 'domain.defaultuseraliases' while deleting alias
          account.
        - List user email in 'domain.defaultuseraliases' which is not exist.

    * Fixed:
        - Permission denied if normal admin create user/alias from main
          navigation bar: Add account -> User/Alias.
          Thanks Chris Ip <chris.ip@>.
        - Incorrect SQL queries which use unindexed content (column 'time_num'
          in table 'amavisd.msgs'.
        - Incorrect mail forwarding address list in user profile page.
          Thanks Alexandre Silva <asilva@> for bug report and testing.
        - Do not add exist domain name as alias domain.
        - Use specified MySQL host instead of 'localhost'.
          Thanks atros@forum <christian@>.
        - Add alias account for new users: address=goto. So that catch-all
          account will work as expected.
        - Incorrect SQL command used to query catch-all address in domain
          profile.
        - Allow normal admin to release/delete their quarantined mails.
        - Incorrect count of quarantined mails.
        - Unable to expand quarantined mails which has '+' in mail_id.


    * Translations:
        - Update French (fr_FR). Thanks Olivier PLOIX <olivier.ploix _at_
          isma-fr.com>

= 1.0.0 =
    * Initial release.
        - List all accounts (domains/admins/users/aliases).
        - Add/delete/enable/disable account (domain/admin/user/alias).
        - View/update account profile (domain/admin/user/alias).
        - Show number of total domains, users, alias in dashboard.
        - User authentication against MySQL (MD5).
        - Log major operations in database.
        - Amavisd integration.
        - Policyd integration.
