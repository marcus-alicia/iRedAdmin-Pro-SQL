# Cron Jobs

* dump_disclaimer.py

    Dump per-domain disclaimer which stored in LDAP or SQL database.
    It's safe to execute it manually.

* cleanup_amavisd_db.py

    Cleanup old records from Amavisd database. It's safe to execute it manually.

* delete_mailboxes.py

    Delete mailboxes which are scheduled to be removed. The schedule date
    was set while you removed the mail account with iRedAdmin(-Pro).

# Utils

* upgrade_iredadmin.sh

    Upgrade an old iRedAdmin-Pro or iRedAdmin open source edition to current
    release.

* update_mailbox_quota.py

    Update mailbox quota for one user (specified on command line) or bulk users
    (read from a plain text file).

* notify_quarantined_recipients.py

    Notify local recipients (via email) that they have emails quarantined on
    server and not delivered to their mailbox.

* convert_ini_to_py.sh

    Convert old iRedAdmin-Pro config file (.ini format) to the new one.

* migrate_cluebringer_wblist_to_amavisd.py

    Migrate Cluebringer white/blacklists to Amavisd database, and, optionally,
    delete them in Cluebringer database.

    Note: Don't forget to enable iRedAPD plugin `amavisd_wblist` in
    `/opt/iredapd/settings.py`.
