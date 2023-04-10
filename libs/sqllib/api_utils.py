import datetime
from libs import form_utils

from libs.sqllib import general as sql_lib_general
from libs.sqllib import sqlutils

import settings


def get_form_password_dict(form,
                           domain,
                           input_name='password',
                           min_passwd_length=None,
                           max_passwd_length=None):
    """Extract password from form, verify it, return both plain and hashed password.

    >>> get_form_password_dict(form=form,
                               domain='domain.tld',
                               input_name='password',
                               min_passwd_length=None,
                               max_passwd_length=None)
    (True, {'pw_plain', '123456',
            'pw_hash', '{SSHA512}....'})
    """
    if input_name not in form:
        return False, 'NO_PASSWORD'

    # Get min/max password length from domain profile
    if not (min_passwd_length or max_passwd_length):
        qr = sql_lib_general.get_domain_settings(domain=domain)

        if qr[0]:
            ds = qr[1]
            min_passwd_length = ds.get('min_passwd_length', settings.min_passwd_length)
            max_passwd_length = ds.get('max_passwd_length', settings.max_passwd_length)

    qr = form_utils.get_password(form=form,
                                 input_name=input_name,
                                 confirm_pw_input_name=input_name,
                                 min_passwd_length=min_passwd_length,
                                 max_passwd_length=max_passwd_length)

    return qr


def export_sql_record(record, remove_columns=None):
    """Convert some values in SQL format to general string.

    - datetime
    - settings
    """
    for (k, v) in list(record.items()):
        if remove_columns:
            if k in remove_columns:
                record.pop(k)
                continue

        if isinstance(v, datetime.datetime):
            record[k] = v.isoformat()
        elif k == 'settings':
            record[k] = sqlutils.account_settings_string_to_dict(v)

    return record


def export_sql_records(records, remove_columns=None):
    new_records = []

    for rcd in records:
        new_rcd = export_sql_record(record=rcd, remove_columns=remove_columns)
        new_records.append(new_rcd)

    return new_records
