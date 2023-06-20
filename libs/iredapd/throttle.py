# Author: Zhang Huangbin <zhb@iredmail.org>

import web
from libs import iredutils


def get_throttle_setting(account, inout_type='outbound'):
    """Get throttle setting.

    @account -- a valid throttling account
    @inout_type -- inbound, outbound
    """
    setting = {}
    if not iredutils.is_valid_amavisd_address(account):
        return setting

    qr = web.conn_iredapd.select(
        'throttle',
        vars={'account': account, 'inout_type': inout_type},
        where='kind=$inout_type AND account=$account',
        limit=1,
    )

    if qr:
        setting = qr[0]

    return setting


def delete_throttle_setting(account, inout_type):
    if not iredutils.is_valid_amavisd_address(account):
        return False, 'INVALID_ACCOUNT'

    if inout_type not in ['inbound', 'outbound']:
        return False, 'INVALID_INOUT_TYPE'

    if account and inout_type:
        web.conn_iredapd.delete(
            'throttle',
            vars={'account': account, 'inout_type': inout_type},
            where='account=$account AND kind=$inout_type',
        )

        return True,

    return True,


def delete_throttle_tracking(account, inout_type):
    tid = get_throttle_id(account, inout_type)

    if tid:
        try:
            web.conn_iredapd.delete(
                'throttle_tracking',
                vars={'tid': tid},
                where='tid=$tid',
            )
        except Exception as e:
            return False, repr(e)

    return True,


def delete_settings_for_removed_users(mails):
    mails = [str(v).lower() for v in mails if iredutils.is_email(v)]
    if not mails:
        return True,

    try:
        web.conn_iredapd.delete(
            'throttle',
            vars={'mails': mails},
            where="""account IN $mails""",
        )

        web.conn_iredapd.delete(
            'throttle_tracking',
            vars={'mails': mails},
            where="""account IN $mails""",
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
            'throttle',
            vars={'domain': '@' + domain},
            where='account=$domain',
        )

        # Delete settings for all users under this domain
        web.conn_iredapd.delete(
            'throttle',
            vars={'domain': '%@' + domain},
            where="""account LIKE $domain""")

        web.conn_iredapd.delete(
            'throttle_tracking',
            vars={'domain': '%@' + domain},
            where="""account LIKE $domain""",
        )

        return True,
    except Exception as e:
        return False, repr(e)


def get_throttle_id(account, inout_type):
    tid = None

    # get `throttle.id`
    qr = web.conn_iredapd.select(
        'throttle',
        vars={'account': account, 'inout_type': inout_type},
        where='account=$account AND kind=$inout_type',
        limit=1,
    )

    if qr:
        tid = qr[0].id

    return tid


def add_throttle(account,
                 setting,
                 inout_type='inbound'):
    if not setting:
        # Delete tracking and setting
        delete_throttle_tracking(account=account, inout_type=inout_type)
        delete_throttle_setting(account=account, inout_type=inout_type)
        return True,

    # Delete record if
    #   - no period. (period == 0) means disabled
    #   - account mismatch
    #   - account is '@.' (global setting) and no valid setting (all are 0)
    #   - account is not '@.' (not global setting) and no valid setting (all are -1)
    if (not setting.get('period', 0)) \
            or (account != setting.get('account')) \
            or (account == '@.'
                and (not setting.get('max_msgs'))
                and (not setting.get('msg_size'))
                and (not setting.get('max_quota'))
                and (not setting.get("max_rcpts"))) \
            or (account != '@.'
                and setting.get("max_msgs") == -1
                and setting.get("msg_size") == -1
                and setting.get("max_quota") == -1
                and setting.get("max_rcpts") in (None, -1)):
        delete_throttle_tracking(account=account, inout_type=inout_type)
        delete_throttle_setting(account=account, inout_type=inout_type)
    else:
        try:
            # Get `throttle.id` if there's a setting.
            tid = get_throttle_id(account=account, inout_type=inout_type)

            if tid:
                # Update existing setting
                web.conn_iredapd.update(
                    'throttle',
                    vars={'tid': tid},
                    where='id=$tid',
                    **setting)
            else:
                # Add new throttle setting.
                web.conn_iredapd.insert('throttle', **setting)
        except Exception as e:
            return False, repr(e)

    return True,
