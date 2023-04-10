# Author: Zhang Huangbin <zhb@iredmail.org>

import web
import settings
from libs import iredutils
from libs.iredutils import is_valid_amavisd_address


def create_mailaddr(addresses):
    for addr in addresses:
        addr_type = iredutils.is_valid_amavisd_address(addr)
        if addr_type in iredutils.MAILADDR_PRIORITIES:
            try:
                web.conn_amavisd.insert(
                    'mailaddr',
                    priority=iredutils.MAILADDR_PRIORITIES[addr_type],
                    email=addr,
                )
            except:
                pass

    return True


def create_user(account, return_record=True):
    # Create a new record in `amavisd.users`
    addr_type = is_valid_amavisd_address(account)
    try:
        # Use policy_id=0 to make sure it's not linked to any policy.
        web.conn_amavisd.insert(
            'users',
            policy_id=0,
            email=account,
            priority=iredutils.MAILADDR_PRIORITIES[addr_type],
        )

        if return_record:
            qr = web.conn_amavisd.select(
                'users',
                vars={'account': account},
                what='*',
                where='email=$account',
                limit=1,
            )
            return True, qr[0]
        else:
            return True,
    except Exception as e:
        return False, repr(e)


def get_user_record(account, create_if_missing=True):
    try:
        qr = web.conn_amavisd.select(
            'users',
            vars={'email': account},
            what='*',
            where='email=$email',
            limit=1,
        )

        if qr:
            return True, qr[0]
        else:
            if create_if_missing:
                qr = create_user(account=account, return_record=True)

                if qr[0]:
                    return True, qr[1]
                else:
                    return qr
            else:
                return False, 'ACCOUNT_NOT_EXIST'
    except Exception as e:
        return False, repr(e)


def create_policy(account, return_record=True):
    # Create a new record in `amavisd.policy`
    try:
        values = {
            'policy_name': account,
            'spam_quarantine_to': 'spam-quarantine',
            'virus_quarantine_to': 'virus-quarantine',
            'spam_subject_tag2': settings.AMAVISD_SPAM_SUBJECT_PREFIX,
        }

        web.conn_amavisd.insert('policy', **values)

        # Update `policy.spam_tag3_level` and `policy.spam_subject_tag3`
        # separately, these two columns don't exist in Amavisd-new-2.6.x.
        try:
            extra_values = {'spam_subject_tag3': settings.AMAVISD_SPAM_SUBJECT_PREFIX}
            web.conn_amavisd.update(
                'policy',
                vars={'policy_name': account},
                where='policy_name=$policy_name',
                **extra_values)
        except:
            pass

        if return_record:
            qr = web.conn_amavisd.select(
                'policy',
                vars={'account': account},
                what='*',
                where='policy_name=$account',
                limit=1,
            )
            return True, qr[0]
        else:
            return True,
    except Exception as e:
        return False, repr(e)


def get_policy_record(account, create_if_missing=False):
    try:
        qr = web.conn_amavisd.select(
            'policy',
            vars={'account': account},
            what='id',
            where='policy_name=$account',
            limit=1,
        )

        if qr:
            return True, qr[0]
        else:
            if create_if_missing:
                qr = create_policy(account=account, return_record=True)

                if qr[0]:
                    return True, qr[1]
                else:
                    return qr
            else:
                return True, {}
    except Exception as e:
        return False, repr(e)


def link_policy_to_user(account, policy_id):
    qr = get_user_record(account)
    if qr[0]:
        user_id = qr[1].id
    else:
        return qr

    try:
        web.conn_amavisd.update(
            'users',
            vars={'id': user_id},
            policy_id=policy_id,
            where='id=$id',
        )
        return True,
    except Exception as e:
        return False, repr(e)


def delete_policy_accounts(accounts):
    sqlvars = {'accounts': accounts}
    try:
        # Get mailaddr.id of accounts
        qr = web.conn_amavisd.select(
            'users',
            vars=sqlvars,
            what='id',
            where='email IN $accounts',
        )

        ids = []
        for i in qr:
            ids.append(i.id)

        # Delete wblist
        web.conn_amavisd.delete(
            'wblist',
            vars={'ids': ids},
            where='rid IN $ids',
        )

        # Delete outbound wblist
        web.conn_amavisd.delete(
            'outbound_wblist',
            vars={'ids': ids},
            where='sid IN $ids',
        )

        # Delete policy
        web.conn_amavisd.delete(
            'policy',
            vars=sqlvars,
            where='policy_name IN $accounts',
        )

        # Delete users
        web.conn_amavisd.delete(
            'users',
            vars=sqlvars,
            where='email IN $accounts',
        )
    except Exception as e:
        return False, repr(e)

    return True,
