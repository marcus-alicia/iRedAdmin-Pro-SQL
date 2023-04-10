# Author: Zhang Huangbin <zhb@iredmail.org>

import web
import settings

from libs import form_utils
from libs.iredutils import is_valid_amavisd_address
from libs.amavisd import utils

session = web.config.get('_session')

DEFAULT_SPAM_TAG_LEVEL = 2
DEFAULT_SPAM_TAG2_LEVEL = 6

# Builtin ban rule names.
BUILTIN_BAN_RULE_NAMES = [
    "ALLOW_MS_OFFICE",
    "ALLOW_MS_WORD",
    "ALLOW_MS_EXCEL",
    "ALLOW_MS_PPT",
]


def delete_spam_policy(account):
    account = str(account).lower()

    if not is_valid_amavisd_address(account):
        return False, 'INVALID_ACCOUNT'

    try:
        web.conn_amavisd.delete('policy',
                                vars={'account': account},
                                where='policy_name=$account')

        return True,
    except Exception as e:
        return False, repr(e)


def get_spam_policy(account='@.'):
    account = str(account).lower()

    if not is_valid_amavisd_address(account):
        return False, 'INVALID_ACCOUNT'

    try:
        sql_where = 'users.policy_id=policy.id AND users.email=$account'
        qr = web.conn_amavisd.select(
            ['policy', 'users'],
            vars={'account': account},
            what='policy.*, users.id AS users_id',
            where=sql_where,
            limit=1,
        )
        if qr:
            policy = qr[0]
            return True, policy
        else:
            return True, {}
    except Exception as e:
        return False, repr(e)


def get_global_spam_score():
    score = DEFAULT_SPAM_TAG2_LEVEL

    (success, policy) = get_spam_policy(account='@.')
    if success and policy:
        score = policy.get('spam_tag2_level', DEFAULT_SPAM_TAG2_LEVEL)

    return score


def update_spam_policy(account, form):
    account = str(account).lower()

    if not is_valid_amavisd_address(account):
        return False, 'INVALID_ACCOUNT'

    if 'delete_policy' in form:
        try:
            web.conn_amavisd.delete(
                'policy',
                vars={'account': account},
                where='policy_name=$account',
            )

            return True,
        except Exception as e:
            return False, repr(e)

    qr = utils.get_policy_record(account=account, create_if_missing=True)
    if qr[0]:
        policy_id = qr[1].id
    else:
        return qr

    # Update spam policy
    updates = {
        'spam_lover': 'N',
        'virus_lover': 'N',
        'banned_files_lover': 'N',
        'bad_header_lover': 'N',
        'bypass_spam_checks': 'N',
        'bypass_virus_checks': 'N',
        'bypass_banned_checks': 'N',
        'bypass_header_checks': 'N',
        'banned_rulenames': "",
    }

    if 'enable_spam_checks' not in form:
        updates['bypass_spam_checks'] = 'Y'

    if 'enable_virus_checks' not in form:
        updates['bypass_virus_checks'] = 'Y'

    if 'enable_banned_checks' not in form:
        updates['bypass_banned_checks'] = 'Y'

    if 'enable_header_checks' not in form:
        updates['bypass_header_checks'] = 'Y'

    updates['spam_quarantine_to'] = ''
    updates['virus_quarantine_to'] = 'virus-quarantine'
    updates['banned_quarantine_to'] = ''
    updates['bad_header_quarantine_to'] = ''

    if 'spam_quarantine_to' in form:
        updates['spam_quarantine_to'] = 'spam-quarantine'
    # else:
    #    updates['spam_lover'] = 'Y'

    if 'virus_quarantine_to' not in form:
        # Deliver virus to mailbox.
        updates['virus_lover'] = 'Y'
        updates['virus_quarantine_to'] = ''

    if 'banned_quarantine_to' in form:
        updates['banned_quarantine_to'] = 'banned-quarantine'
    # else:
    #    updates['banned_files_lover'] = 'Y'

    if 'bad_header_quarantine_to' in form:
        updates['bad_header_quarantine_to'] = 'bad-header-quarantine'
    else:
        updates['bad_header_lover'] = 'Y'

    # Modify spam subject
    if 'modify_spam_subject' in form:
        updates['spam_subject_tag2'] = settings.AMAVISD_SPAM_SUBJECT_PREFIX
    else:
        updates['spam_subject_tag2'] = None

    updates['spam_tag_level'] = None
    updates['spam_tag2_level'] = None
    updates['spam_kill_level'] = None

    if account == '@.' and 'always_insert_x_spam_headers' in form:
        updates['spam_tag_level'] = -100

    for p in ['spam_tag2_level', 'spam_kill_level']:
        _score = form.get(p, '')

        if _score:
            try:
                updates[p] = float(_score)
            except:
                pass

    if "banned_rulenames" in form:
        names = form.get("banned_rulenames", [])
        new_names = set()

        for n in names:
            if (n in BUILTIN_BAN_RULE_NAMES) or (n in settings.AMAVISD_BAN_RULES):
                new_names.add(n)

        # Sort the result for easier unittest.
        new_names = sorted(new_names)

        updates["banned_rulenames"] = ",".join(new_names)

    try:
        web.conn_amavisd.update(
            'policy',
            vars={'id': policy_id},
            where='id=$id',
            **updates)

        qr = utils.link_policy_to_user(account=account, policy_id=policy_id)
        if not qr[0]:
            return qr

        # Update `policy.spam_tag3_level` and `policy.spam_subject_tag3`
        # separately, these two columns don't exist in Amavisd-new-2.6.x.
        try:
            extra_updates = {'spam_tag3_level': updates['spam_tag2_level'],
                             'spam_subject_tag3': updates['spam_subject_tag2']}

            web.conn_amavisd.update(
                'policy',
                vars={'id': policy_id},
                where='id=$id',
                **extra_updates)
        except:
            pass

        return True,
    except Exception as e:
        return False, repr(e)


def api_update_spam_policy(account, form):
    """Create new spam policy or update existing policy."""
    account = str(account).lower()

    if not is_valid_amavisd_address(account):
        return False, 'INVALID_ACCOUNT'

    # Get current `amavisd.policy.id`, it will create a new one if not present.
    qr = utils.get_policy_record(account=account, create_if_missing=True)
    if not qr[0]:
        return qr

    # Set default policy
    policy = {
        'policy_name': account,
        # Default check policy: don't bypass checks
        'bypass_spam_checks': 'N',
        'bypass_virus_checks': 'N',
        'bypass_banned_checks': 'N',
        'bypass_header_checks': 'N',
        # Default quarantining policy: quarantine virus
        'spam_quarantine_to': None,
        'virus_quarantine_to': 'virus-quarantine',
        'banned_quarantine_to': None,
        'bad_header_quarantine_to': None,
        # tags/scores
        'spam_subject_tag': None,
        'spam_subject_tag2': None,
        'spam_tag_level': None,
        'spam_kill_level': None,
        # ban rules.
        "banned_rulenames": "",
    }

    for k in ['spam', 'virus', 'banned', 'header']:
        # Checks: bypass_<k>_checks
        _chk = 'bypass_' + k + '_checks'
        v = form_utils.get_single_value(form, input_name=_chk, to_string=True)
        if v:
            if v == 'yes':
                v = 'Y'     # Exclictly enable
            elif v == 'no':
                v = 'N'     # Exclictly disable
            else:
                v = None    # Don't set a value, use default policy.

            policy[_chk] = v

        # Quarantining: quarantine_<k>
        _quar_input = 'quarantine_' + k
        _quar_key = k + '_quarantine_to'
        if k == 'header':
            _quar_input = 'quarantine_bad_header'
            _quar_key = 'bad_header_quarantine_to'

        v = form_utils.get_single_value(form=form, input_name=_quar_input, to_string=True)
        if v:
            if v == 'yes':
                v = k + '-quarantine'
                if k == 'header':
                    v = 'bad-header-quarantine'
            else:
                v = None

            policy[_quar_key] = v

    # Modify spam subject
    v = form_utils.get_single_value(form=form, input_name='prefix_spam_in_subject', to_string=True)
    if v:
        if v == 'yes':
            policy['spam_subject_tag'] = settings.AMAVISD_SPAM_SUBJECT_PREFIX
            policy['spam_subject_tag2'] = settings.AMAVISD_SPAM_SUBJECT_PREFIX
        else:
            policy['spam_subject_tag'] = None
            policy['spam_subject_tag2'] = None

    v = form_utils.get_single_value(form=form, input_name='always_insert_x_spam_headers', to_string=True)
    if v:
        if v == 'yes':
            policy['spam_tag_level'] = -100
        else:
            policy['spam_tag_level'] = None

    v = form_utils.get_single_value(form=form, input_name='spam_score', to_string=True)
    if v.isdigit():
        try:
            _score = float(v)
            policy['spam_tag2_level'] = _score
            policy['spam_kill_level'] = _score
        except:
            return False, 'INVALID_SPAM_SCORE'

    # Get ban rules.
    names = form_utils.get_multi_values_from_api(form,
                                                 input_name="banned_rulenames",
                                                 to_string=True,
                                                 to_lowercase=False)
    if names:
        new_names = set()
        for n in names:
            if (n in BUILTIN_BAN_RULE_NAMES) or (n in settings.AMAVISD_BAN_RULES):
                new_names.add(n)

        policy["banned_rulenames"] = ",".join(new_names)

    qr = delete_spam_policy(account=account)
    if not qr[0]:
        return qr

    # column `users_id` is not a column name in `amavisd.policy` table,
    # it's set by SQL statement `LEFT JOIN`.
    if 'users_id' in policy:
        policy.pop('users_id')

    try:
        policy_id = web.conn_amavisd.insert('policy', **policy)

        qr = utils.link_policy_to_user(account=account, policy_id=policy_id)
        if not qr[0]:
            return qr

        # Update `policy.spam_tag3_level` and `policy.spam_subject_tag3`
        # separately, these two columns don't exist in Amavisd-new-2.6.x.
        try:
            extra_updates = {'spam_tag3_level': policy['spam_tag2_level'],
                             'spam_subject_tag3': policy['spam_subject_tag2']}

            web.conn_amavisd.update(
                'policy',
                vars={'id': policy_id},
                where='id=$id',
                **extra_updates)
        except:
            pass

        return True,
    except Exception as e:
        return False, repr(e)
