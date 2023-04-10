# Author: Zhang Huangbin <zhb@iredmail.org>

from typing import Dict


def account_settings_dict_to_string(account_settings: Dict) -> str:
    # Convert account setting dict to string.
    # - dict: {'var': 'value', 'var2: value2', ...}
    # - string: 'var:value;var2:value2;...'
    if not account_settings or not isinstance(account_settings, dict):
        return ''

    for (k, v) in list(account_settings.items()):
        if k in ['default_groups',
                 'default_mailing_lists',
                 'enabled_services',
                 'disabled_mail_services',
                 'disabled_domain_profiles',
                 'disabled_user_profiles',
                 'disabled_user_preferences']:
            if isinstance(v, (list, tuple, set)):
                if isinstance(v, list):
                    v.sort()
                elif isinstance(v, set):
                    v = list(v)
                    v.sort()

                account_settings[k] = ','.join(v)
            else:
                # Remove item if value is not a list/tuple/set
                account_settings.pop(k)

    new_settings = ';'.join(['{}:{}'.format(str(i), j) for (i, j) in list(account_settings.items()) if j])

    if new_settings:
        new_settings += ';'

    return new_settings


def account_settings_string_to_dict(account_settings: str) -> Dict:
    # Convert account setting (string, format 'var:value;var2:value2;...', used
    # in MySQL/PGSQL backends) to dict.
    #   - domain.settings
    #   - mailbox.settings
    # Original setting must be a string
    if not account_settings:
        return {}

    new_settings = {}

    items = [st for st in account_settings.split(';') if ':' in st]
    for item in items:
        if item:
            (k, v) = item.split(':')
            if v:
                new_settings[k] = v

    # Convert value to proper format (int, string, ...), default is string.
    # It will be useful to compare values with converted values.
    # If original value is not stored in proper format, key:value pair will
    # be removed.
    for key in new_settings:
        # integer
        if key in ['default_user_quota',
                   'max_user_quota',
                   'min_passwd_length',
                   'max_passwd_length',
                   # settings used to create new domains.
                   'create_max_domains',
                   'create_max_users',
                   'create_max_lists',
                   'create_max_aliases',
                   'create_max_quota']:
            try:
                new_settings[key] = int(new_settings[key])
            except:
                new_settings.pop(key)

        # list
        if key in ['enabled_services',
                   'disabled_mail_services',
                   'default_groups',
                   'default_mailing_lists',
                   'disabled_domain_profiles',
                   'disabled_user_profiles',
                   'disabled_user_preferences']:
            new_settings[key] = [str(i) for i in new_settings[key].split(',') if i]

    return new_settings
