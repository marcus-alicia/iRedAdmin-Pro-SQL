# Author: Zhang Huangbin <zhb@iredmail.org>

import web

from libs import iredutils
from libs.logger import logger


def get_all_greylist_settings():
    """Return all existing greylisting settings."""
    gl_settings = {}

    try:
        qr = web.conn_iredapd.select(
            'greylisting',
            what='id, account, sender, active',
        )
        if qr:
            gl_settings = list(qr)
    except Exception as e:
        logger.error(e)

    return gl_settings


def get_greylist_setting(account=None):
    """Return greylisting setting of specified account."""
    gl_setting = {}

    if not account:
        account = '@.'

    if not iredutils.is_valid_amavisd_address(account):
        return gl_setting

    try:
        qr = web.conn_iredapd.select(
            'greylisting',
            vars={'account': account},
            what='id, account, sender, active',
            where="""account = $account AND sender='@.'""",
            limit=1,
        )

        if qr:
            gl_setting = qr[0]
    except Exception as e:
        logger.error(e)

    return gl_setting


def get_greylist_whitelists(account, address_only=False):
    """Return greylisting whitelists of specified account."""
    if not iredutils.is_valid_amavisd_address(account):
        return []

    whitelists = []
    try:
        qr = web.conn_iredapd.select(
            'greylisting_whitelists',
            vars={'account': account},
            what='id, sender, comment',
            where='account = $account',
            order='sender',
        )
        if qr:
            whitelists = list(qr)

        # Don't explore SQL structure, just export the sender addresses
        if address_only and whitelists:
            wl = []
            for i in whitelists:
                wl.append(i.sender.lower())

            whitelists = wl

    except Exception as e:
        logger.error(e)

    return whitelists


def get_greylist_whitelist_domains():
    """Return greylisting whitelist domains of specified account."""
    domains = []

    try:
        qr = web.conn_iredapd.select(
            'greylisting_whitelist_domains',
            what='domain',
            order='domain',
        )
        if qr:
            for i in qr:
                domains.append(str(i.domain).lower())
    except Exception as e:
        logger.error(e)

    return domains


def delete_greylist_setting(account, senders=None):
    """Delete greylisting setting of specified account."""
    if not iredutils.is_valid_amavisd_address(account):
        return True

    try:
        if senders:
            web.conn_iredapd.delete(
                'greylisting',
                vars={'account': account, 'senders': senders},
                where="""account = $account AND sender IN $sender""",
            )
        else:
            web.conn_iredapd.delete(
                'greylisting',
                vars={'account': account},
                where="""account = $account""",
            )
        return True,
    except Exception as e:
        return False, repr(e)


def enable_disable_greylist_setting(account, enable=False):
    """Update (or create) greylisting setting of specified account."""
    account_type = iredutils.is_valid_amavisd_address(account)
    if not account_type:
        return False, 'INVALID_ACCOUNT'

    active = 0
    if enable:
        active = 1

    gl_setting = {'account': account,
                  'priority': iredutils.IREDAPD_ACCOUNT_PRIORITIES.get(account_type, 0),
                  'sender': '@.',
                  'sender_priority': 0,
                  'active': active}

    try:
        # Delete existing record first.
        web.conn_iredapd.delete(
            'greylisting',
            vars={'account': account, 'sender': gl_setting['sender']},
            where='account = $account AND sender = $sender',
        )

        # Create new record
        web.conn_iredapd.insert('greylisting', **gl_setting)
    except Exception as e:
        return False, repr(e)

    return True,


def reset_greylist_whitelist_domains(domains=None):
    """Update greylisting whitelist domains for specified account.

    @domains -- must be a list/tuple/set
    @conn -- sql connection cursor
    """
    # Delete existing records first
    try:
        web.conn_iredapd.delete('greylisting_whitelist_domains', where='1=1')
    except Exception as e:
        return False, repr(e)

    # Insert new records
    if domains:
        values = []
        for d in domains:
            values += [{'domain': d}]

        try:
            web.conn_iredapd.multiple_insert('greylisting_whitelist_domains', values=values)
        except Exception as e:
            return False, repr(e)

    return True, 'GL_WLD_UPDATED'


def update_greylist_whitelist_domains(new=None, removed=None):
    """Add new or remove existing whitelist SPF domains for greylisting service.

    @new - must be a list/tuple/set of sender domains
    @removed - must be a list/tuple/set of sender domains
    @conn - sql connection cursor
    """
    _new = []
    if new:
        _new = [str(i).lower()
                for i in new
                if iredutils.is_domain(i)]
        _new = list(set(_new))

    _removed = []
    if removed:
        _removed = [str(i).lower()
                    for i in removed
                    if iredutils.is_domain(i)]
        _removed = list(set(_removed))

        # Remove duplicates
        _removed = [i for i in _removed if i not in _new]

    if not (_new or _removed):
        return True,

    # Insert new whitelists
    if _new:
        for i in _new:
            try:
                web.conn_iredapd.insert('greylisting_whitelist_domains', domain=i)
            except Exception as e:
                logger.error(e)

    # Remove existing ones
    if _removed:
        try:
            web.conn_iredapd.delete(
                'greylisting_whitelist_domains',
                vars={'removed': _removed},
                where='domain IN $removed',
            )
        except Exception as e:
            logger.error(e)

    return True,


def reset_greylist_whitelists(account, whitelists=None):
    """Reset greylisting whitelists for specified account.

    If `whitelists` is empty, all existing whitelists will be removed.

    @whitelists - must be a list/tuple/set of whitelist senders, or a list of
                  dict which maps to sql column/value pairs. e.g.
                  [{'account': '@.',
                    'sender': '192.168.1.1',
                    'comment': ''},
                    ...]
    """
    if not iredutils.is_valid_amavisd_address(account):
        return False, 'INVALID_ACCOUNT'

    # Delete existing whitelists first
    try:
        web.conn_iredapd.delete(
            'greylisting_whitelists',
            vars={'account': account},
            where='account = $account',
        )
    except Exception as e:
        return False, repr(e)

    # Insert new whitelists
    if whitelists:
        for w in whitelists:
            if isinstance(w, dict):
                try:
                    web.conn_iredapd.insert('greylisting_whitelists', **w)
                except:
                    pass
            elif isinstance(w, str):
                try:
                    web.conn_iredapd.insert(
                        'greylisting_whitelists',
                        account=account,
                        sender=w,
                    )
                except:
                    pass

    return True,


def update_greylist_whitelists(account, new=None, removed=None):
    """Add new or remove existing greylisting whitelists for specified account.

    :param account: must be an valid iRedAPD account
    :param new: must be a list/tuple/set of whitelist senders
    :param removed: must be a list/tuple/set of whitelist senders
    """
    if not iredutils.is_valid_amavisd_address(account):
        return False, 'INVALID_ACCOUNT'

    _new = []
    if new:
        _new = [str(i).lower()
                for i in new
                if iredutils.is_valid_wblist_address(i)]
        _new = list(set(_new))

    _removed = []
    if removed:
        _removed = [str(i).lower()
                    for i in removed
                    if iredutils.is_valid_wblist_address(i)]
        _removed = list(set(_removed))

        # Remove duplicates
        _removed = [i for i in _removed if i not in _new]

    if not (_new or _removed):
        return True,

    # Insert new whitelists
    if _new:
        for w in _new:
            try:
                web.conn_iredapd.insert(
                    'greylisting_whitelists',
                    account=account,
                    sender=w,
                )
            except:
                pass

    # Remove existing ones
    if _removed:
        try:
            web.conn_iredapd.delete(
                'greylisting_whitelists',
                vars={'removed': removed},
                where='sender IN $removed',
            )
        except:
            pass

    return True,


def update_greylist_settings_from_form(account, form):
    # Enable/disable greylisting
    #   @inherit - inherit from global setting
    #   @enable  - explicitly enable
    #   @disable  - explicitly disable
    _gl_value = form.get('greylisting', 'inherit')
    if _gl_value == 'inherit':
        # Delete greylisting setting
        qr = delete_greylist_setting(account=account)
    elif _gl_value == 'enable':
        qr = enable_disable_greylist_setting(account=account, enable=True)
    elif _gl_value == 'disable':
        qr = enable_disable_greylist_setting(account=account, enable=False)
    else:
        return True, 'GL_UPDATED'

    if qr[0] is not True:
        return qr

    # Update greylisting whitelist domains.
    if account == '@.':
        wl_domains = set()
        lines = form.get('whitelist_domains', '').splitlines()
        for line in lines:
            if iredutils.is_domain(line):
                wl_domains.add(str(line).lower())

        qr = reset_greylist_whitelist_domains(domains=wl_domains)
        if not qr[0]:
            return qr

    # Update greylisting whitelists.
    whitelists = []

    # Store senders to avoid duplicate
    _senders = set()
    lines = form.get('whitelists', '').splitlines()
    for line in lines:
        # Split sender and comment with '#'
        wl = line.split('#', 1)

        sender = ''
        comment = ''

        if len(wl) == 1:
            sender = str(wl[0]).strip()
            comment = ''
        elif len(wl) == 2:
            sender = str(wl[0]).strip()
            comment = wl[1].strip()

        # Validate sender.
        if not iredutils.is_valid_wblist_address(sender):
            continue

        if sender not in _senders:
            whitelists += [{'account': account, 'sender': sender, 'comment': comment}]
            _senders.add(sender)

    qr = reset_greylist_whitelists(account=account, whitelists=whitelists)
    if qr[0]:
        return True, 'GL_UPDATED'
    else:
        return qr


def delete_settings_for_removed_users(mails):
    mails = [str(v).lower() for v in mails if iredutils.is_email(v)]
    if not mails:
        return True,

    try:
        # Delete settings for user
        web.conn_iredapd.delete(
            'greylisting',
            vars={'mails': mails},
            where="""account IN $mails""",
        )

        # Delete whitelists
        web.conn_iredapd.delete(
            'greylisting_whitelists',
            vars={'mails': mails},
            where='account IN $mails',
        )

        # Delete greylisting tracking
        web.conn_iredapd.delete(
            'greylisting_tracking',
            vars={'mails': mails},
            where="""recipient IN $mails""",
        )

        return True,
    except Exception as e:
        return False, repr(e)


def delete_settings_for_removed_domain(domain):
    if not iredutils.is_domain(domain):
        return True,

    try:
        # Delete settings for domain ('@domain.com')
        web.conn_iredapd.delete(
            'greylisting',
            vars={'domain': '@' + domain},
            where='account=$domain',
        )

        # Delete settings for all users under this domain
        web.conn_iredapd.delete(
            'greylisting',
            vars={'domain': '%@' + domain},
            where="""account LIKE $domain""",
        )

        # Delete whitelists
        web.conn_iredapd.delete(
            'greylisting_whitelists',
            vars={'domain': '@' + domain},
            where='account=$domain',
        )

        web.conn_iredapd.delete(
            'greylisting_whitelists',
            vars={'domain': '%@' + domain},
            where='account LIKE $domain',
        )

        # Delete greylisting tracking
        web.conn_iredapd.delete(
            'greylisting_tracking',
            vars={'domain': domain},
            where='rcpt_domain=$domain',
        )

        return True,
    except Exception as e:
        return False, repr(e)


def get_tracking_data(account):
    """Get tracking data of given local account."""
    _account_type = iredutils.is_valid_amavisd_address(account)
    if not _account_type:
        return True, []

    try:
        if _account_type == 'catchall':
            # account = '@.'
            qr = web.conn_iredapd.select(
                'greylisting_tracking',
                what='COUNT(blocked_count) AS total, sender_domain',
                where='passed=0',
                group='sender_domain',
                order='total DESC',
            )

        elif _account_type == 'domain':
            domain = account.lstrip('@')
            qr = web.conn_iredapd.select(
                'greylisting_tracking',
                vars={'domain': domain},
                where='sender_domain=$domain AND passed=0',
                order='init_time DESC',
            )
        else:
            return False, 'INVALID_ACCOUNT'

        return True, list(qr)
    except Exception as e:
        return False, repr(e)


def get_domain_tracking_data(domain):
    """Get tracking data of given domain."""
    domain = str(domain).lower()
    return get_tracking_data(account='@' + domain)


def filter_whitelisted_ips(ips):
    """Return list of (globally) whitelisted IPs."""
    ips = [i for i in ips if iredutils.is_strict_ip(i)]
    if not ips:
        return True, []

    try:
        qr = web.conn_iredapd.select(
            'greylisting_whitelists',
            vars={'account': '@.', 'ips': ips},
            what='sender',
            where='account=$account AND sender IN $ips',
            order='sender',
        )
        whitelisted_ips = [i.sender for i in qr]

        return True, whitelisted_ips
    except Exception as e:
        logger.error(e)
        return False, repr(e)
