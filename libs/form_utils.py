"""Functions used to extract required data from web form."""

import settings
from libs import iredutils, iredpwd
from libs.l10n import TIMEZONES


# Return single value of specified form name.
def get_single_value(form,
                     input_name,
                     default_value='',
                     is_domain=False,
                     is_email=False,
                     is_integer=False,
                     is_strict_ip=False,
                     is_ip_or_network=False,
                     to_lowercase=False,
                     to_uppercase=False,
                     to_string=False,
                     split_value=False,
                     split_separator=None,
                     strip_str_before_split=False,
                     strip_str=None):
    v = form.get(input_name, '')
    if not v:
        v = default_value

    if not isinstance(v, (int, float)):
        try:
            v = v.strip()
        except:
            pass

    if is_domain:
        if not iredutils.is_domain(v):
            return ''

    if is_email:
        if not iredutils.is_email(v):
            v = default_value

    if is_integer:
        try:
            v = int(v)
        except:
            v = default_value

    if is_strict_ip:
        if not iredutils.is_strict_ip(v):
            return ''

    if is_ip_or_network:
        if not iredutils.is_ip_or_network(v):
            return ''

    if to_string:
        try:
            if isinstance(v, (list, tuple)):
                v = [str(i) for i in v]
            else:
                v = str(v)
        except:
            pass

    if to_lowercase:
        if isinstance(v, (list, tuple)):
            v = [i.lower() for i in v]
        else:
            v = v.lower()

    if to_uppercase:
        if isinstance(v, (list, tuple)):
            v = [i.upper() for i in v]
        else:
            v = v.upper()

    if split_value:
        # return a list
        if isinstance(v, str):
            if strip_str_before_split:
                if not strip_str:
                    strip_str = ' '

                v.strip(strip_str)

            if split_separator:
                v = v.split(split_separator)
            else:
                v = v.split()

            # Remove empty values
            v = [i for i in v if i]

    return v


# Return single value of specified form name.
def get_multi_values(form,
                     input_name,
                     default_value=None,
                     input_is_textarea=False,
                     is_domain=False,
                     is_email=False,
                     is_ip_or_network=False,
                     to_lowercase=False,
                     to_uppercase=False,
                     to_string=False):
    v = form.get(input_name)
    if v:
        if input_is_textarea:
            v = v.splitlines()
            v = [i.strip() for i in v]
    else:
        if default_value is None:
            v = []
        else:
            v = default_value

    # Remove duplicate items.
    try:
        v = list(set(v))
    except:
        v = []

    if is_domain:
        v = [str(i).lower() for i in v if iredutils.is_domain(i)]

    if is_email:
        v = [str(i).lower() for i in v if iredutils.is_email(i)]

    if is_ip_or_network:
        v = [str(i) for i in v if iredutils.is_ip_or_network(i)]

    if to_lowercase:
        if not (is_domain or is_email):
            v = [i.lower() for i in v]

    if to_uppercase:
        if not (is_domain or is_email):
            v = [i.upper() for i in v]

    if to_string:
        v = [str(i) for i in v]

    v.sort()
    return v


def get_multi_values_from_api(form,
                              input_name,
                              to_string=True,
                              to_lowercase=True,
                              is_domain=False,
                              is_email=False):
    """Param/value posted from API will be: key=value1,value2,value3,...
    This function extract values and return them as a list.
    """
    values = get_single_value(form=form,
                              input_name=input_name,
                              to_string=to_string,
                              to_lowercase=to_lowercase,
                              split_value=True,
                              split_separator=',',
                              strip_str_before_split=True)

    if is_domain:
        values = [i for i in values if iredutils.is_domain(i)]

    if is_email:
        values = [i for i in values if iredutils.is_email(i)]

    return list(set(values))


def get_multi_values_from_textarea(form,
                                   input_name,
                                   is_domain=False,
                                   is_email=False,
                                   to_lowercase=False):
    """Param/value posted from API will be: key=value1,value2,value3,...
    This function extract values and return them as a list.
    """
    v = get_single_value(form=form,
                         input_name=input_name,
                         to_string=True,
                         to_lowercase=to_lowercase,
                         split_value=True,
                         split_separator=None,
                         strip_str_before_split=True)

    if is_domain:
        v = [i for i in v if iredutils.is_domain(i)]

    if is_email:
        v = [i for i in v if iredutils.is_email(i)]

    return v


def get_form_dict(form,
                  input_name,
                  key_name=None,
                  multi_values=False,
                  default_value='',
                  input_is_textarea=False,
                  is_domain=False,
                  is_email=False,
                  is_integer=False,
                  to_lowercase=False,
                  to_uppercase=False,
                  to_string=False):
    d = {}
    if input_name in form:
        if multi_values:
            # Value is a list
            v = get_multi_values(form,
                                 input_name,
                                 default_value=default_value,
                                 input_is_textarea=input_is_textarea,
                                 is_domain=is_domain,
                                 is_email=is_email,
                                 to_lowercase=to_lowercase,
                                 to_uppercase=to_uppercase)
        else:
            v = get_single_value(form,
                                 input_name=input_name,
                                 default_value=default_value,
                                 is_domain=is_domain,
                                 is_email=is_email,
                                 is_integer=is_integer,
                                 to_lowercase=to_lowercase,
                                 to_uppercase=to_uppercase,
                                 to_string=to_string)

        # Convert values of some parameters
        if settings.backend == 'ldap':
            if input_name == 'accountStatus':
                # When 'accountStatus' is used by a checkbox, its value will
                # be 'on' which means the checkbox is checked.
                if v in ['enable', 'active', 'yes', 'on', 1]:
                    v = 'active'
                else:
                    v = 'disabled'
            elif input_name == 'isGlobalAdmin':
                if v != 'yes':
                    v = None
            elif input_name in ['quota', 'defaultQuota', 'maxUserQuota',
                                'minPasswordLength', 'maxPasswordLength',
                                'numberOfUsers', 'numberOfAliases',
                                'numberOfLists']:
                # Require integer number
                try:
                    v = int(v)
                except:
                    # Don't return any value.
                    return {}

        else:
            if input_name in ['accountStatus', 'backupmx']:
                if v in ['enable', 'active', 'yes', 1]:
                    v = 1
                else:
                    v = 0

        if key_name:
            d[key_name] = v
        else:
            if settings.backend == 'ldap':
                # Map some input names to LDAP attribute names
                # Warning: do not map the key names used in accountSetting.
                if input_name == 'name':
                    key_name = 'cn'
                elif input_name == 'accountStatus':
                    key_name = input_name
                elif input_name == 'language':
                    key_name = 'preferredLanguage'
                elif input_name == 'transport':
                    key_name = 'mtaTransport'
                else:
                    key_name = input_name
            else:
                key_name = input_name

            d[key_name] = v

    return d


def get_name(form, input_name='cn'):
    return get_single_value(form,
                            input_name=input_name,
                            default_value='')


def get_domain_name(form, input_name='domainName'):
    return get_single_value(form,
                            input_name=input_name,
                            default_value='',
                            is_domain=True,
                            to_lowercase=True,
                            to_string=True)


def get_domain_names(form, input_name='domainName'):
    return get_multi_values(form,
                            input_name=input_name,
                            default_value=[],
                            is_domain=True,
                            to_lowercase=True)


# Get default language for new mail user from web form.
def get_language(form, input_name='preferredLanguage'):
    lang = get_single_value(form, input_name=input_name, to_string=True)
    if lang not in iredutils.get_language_maps():
        lang = ''

    return lang


def get_domain_quota_and_unit(form,
                              input_quota='domainQuota',
                              input_quota_unit='domainQuotaUnit',
                              convert_to_mb=True):
    """Get domain quota and quota unit from web form, return a dict contains
    quota (in MB) and ORIGINAL quota unit: {'quota': <integer>, 'unit': <string>}.
    """
    # multiply is used for SQL backends.
    quota = str(form.get(input_quota))
    if quota.isdigit():
        quota = abs(int(quota))
    else:
        quota = 0

    quota_unit = str(form.get(input_quota_unit, 'MB'))
    if quota > 0:
        # Convert to MB
        if convert_to_mb:
            if quota_unit == 'GB':
                quota = quota * 1024
            elif quota_unit == 'TB':
                quota = quota * 1024 * 1024

    return {'quota': quota, 'unit': quota_unit}


# Get mailbox quota (in MB).
def get_quota(form, input_name='defaultQuota', default=0):
    quota = str(form.get(input_name))
    if quota.isdigit():
        quota = abs(int(quota))

        if input_name == 'maxUserQuota':
            quota_unit = str(form.get('maxUserQuotaUnit', 'MB'))
            if quota_unit == 'TB':
                quota = quota * 1024 * 1024
            elif quota_unit == 'GB':
                quota = quota * 1024
            else:
                # MB
                pass
    else:
        quota = default

    return quota


def get_account_status(form,
                       input_name='accountStatus',
                       default_value='active',
                       to_integer=False):
    status = get_single_value(form, input_name=input_name, to_string=True)

    if not (status in ['active', 'disabled']):
        status = default_value

    # SQL backends store the account status as `active=[1|0]`
    # LDAP backends store the account status as `accountStatus=[active|disabled]`
    if to_integer:
        if status == 'active':
            return 1
        else:
            return 0
    else:
        return status


def get_password(form,
                 input_name='newpw',
                 confirm_pw_input_name='confirmpw',
                 min_passwd_length=None,
                 max_passwd_length=None):
    pw = get_single_value(form,
                          input_name=input_name,
                          to_string=True)

    confirm_pw = get_single_value(form,
                                  input_name=confirm_pw_input_name,
                                  to_string=True)

    qr = iredpwd.verify_new_password(newpw=pw,
                                     confirmpw=confirm_pw,
                                     min_passwd_length=min_passwd_length,
                                     max_passwd_length=max_passwd_length)
    if not qr[0]:
        return qr

    if 'store_password_in_plain_text' in form and settings.STORE_PASSWORD_IN_PLAIN:
        pw_hash = iredpwd.generate_password_hash(pw, pwscheme='PLAIN')
    else:
        pw_hash = iredpwd.generate_password_hash(pw)

    return True, {'pw_plain': pw, 'pw_hash': pw_hash}


def get_timezone(form, input_name='timezone'):
    tz = get_single_value(form,
                          input_name=input_name,
                          to_string=True)

    if tz in TIMEZONES:
        return tz

    return None


def get_list_access_policy(form,
                           input_name='accessPolicy',
                           default_value='public'):
    policy = get_single_value(form=form,
                              input_name=input_name,
                              default_value=default_value,
                              to_string=True)

    if policy not in iredutils.MAILLIST_ACCESS_POLICIES:
        policy = 'public'

    return policy


# iRedAPD: Get throttle setting for
def get_throttle_setting(form, account, inout_type='inbound'):
    # inout_type -- inbound, outbound.
    var_enable_throttle = 'enable_%s_throttling' % inout_type

    # not enabled.
    if var_enable_throttle not in form:
        return {}

    # name of form <input> tag:
    # [inout_type]_[name]
    # custom_[inout_type]_[name]

    # Pre-defined values
    setting = {'account': account,
               'priority': iredutils.get_account_priority(account),
               'period': 0,
               'max_msgs': 0,
               'max_quota': 0,
               'msg_size': 0,
               'kind': inout_type}

    input_keys = ['period', 'max_msgs', 'max_quota', 'msg_size']

    if inout_type == "outbound":
        setting["max_rcpts"] = 0
        input_keys.append("max_rcpts")

    for k in input_keys:
        var = inout_type + '_' + k

        # Get pre-defined value first
        v = form.get(var, '')

        if v == 'on':
            # Get custom value if it's not pre-defined
            v = form.get('custom_' + var)

        try:
            v = int(v)
            setting[k] = v
        except:
            continue

    # Return empty dict if all values are 0.
    return setting


# NOTE: used by LDAP backends.
def update_domain_creation_settings(form,
                                    account_settings,
                                    check_creation_permission=True):
    """Update `account_settings` with data from form.

    :param form: web form data
    :param account_settings: dict of per-admin account settings
    :param check_creation_permission: check whether html tag
        "<input name='allowed_to_create_domain' ... />" exists, used in user
        profile page.
    """
    _allowed = True
    if check_creation_permission:
        if 'allowed_to_create_domain' not in form:
            _allowed = False

    if _allowed:
        for i in ['create_max_domains',
                  'create_max_quota',
                  'create_max_users',
                  'create_max_aliases',
                  'create_max_lists']:
            if i in form:
                try:
                    v = int(form.get(i, '0'))
                except:
                    v = 0

                if v > 0:
                    account_settings[i] = v
                else:
                    if i in account_settings:
                        account_settings.pop(i)

        for i in ['disable_domain_ownership_verification']:
            if i in form:
                account_settings[i] = 'yes'
            else:
                if i in account_settings:
                    account_settings.pop(i)

        if 'create_max_quota' in account_settings:
            if 'create_quota_unit' in form:
                v = form.get('create_quota_unit', 'TB')
                if v in ['TB', 'GB']:
                    account_settings['create_quota_unit'] = v
                else:
                    if 'create_quota_unit' in account_settings:
                        account_settings.pop('create_quota_unit')

        for i in ['create_max_domains',
                  'create_max_quota',
                  'create_max_users',
                  'create_max_aliases',
                  'create_max_lists']:
            if i in account_settings:
                account_settings['create_new_domains'] = 'yes'
                break
            else:
                # Remove account_settings['create_new_domains']
                try:
                    account_settings.pop('create_new_domains')
                except:
                    pass
    else:
        for i in ['create_new_domains',
                  'create_max_domains',
                  'create_max_quota',
                  'create_max_users',
                  'create_max_aliases',
                  'create_max_lists',
                  'disable_domain_ownership_verification']:
            if i in account_settings:
                account_settings.pop(i)

    return account_settings


# NOTE: used by LDAP backends.
def get_domain_creation_settings(form):
    """Get per-admin domain creation limits from web form."""
    d = {}

    kv = get_form_dict(form=form,
                       input_name='create_max_domains',
                       default_value=0,
                       is_integer=True)
    if kv:
        d.update(kv)
        d['create_new_domains'] = 'yes'

        kv = get_form_dict(form=form,
                           input_name='create_max_users',
                           default_value=0,
                           is_integer=True)
        d.update(kv)

        kv = get_form_dict(form=form,
                           input_name='create_max_aliases',
                           default_value=0,
                           is_integer=True)
        d.update(kv)

        kv = get_form_dict(form=form,
                           input_name='create_max_lists',
                           default_value=0,
                           is_integer=True)
        d.update(kv)

        # format: 10TB, 10GB, 10MB.
        kv = get_form_dict(form=form,
                           input_name='create_max_quota',
                           default_value=0,
                           is_integer=True)

        if kv:
            _kv = get_form_dict(form=form,
                                input_name='create_quota_unit',
                                default_value='MB',
                                to_uppercase=True,
                                to_string=True)
            d.update(_kv)
            d.update(kv)

    # Discard item which has value == '0'
    if d:
        for (k, v) in list(d.items()):
            if v == 0:
                d.pop(k)

                if k == 'create_max_quota':
                    if 'create_quota_unit' in d:
                        d.pop('create_quota_unit')

    return d


#
# mlmmj
#
def get_mlmmj_params_from_web_form(form):
    """Convert parameter names/values in web form to mlmmj parameters."""
    mlmmj_params = form.copy()

    # Remove parameters used by web form but not mlmmjadmin API
    for k in ['csrf_token', 'modified', 'active', 'accountStatus']:
        if k in mlmmj_params:
            mlmmj_params.pop(k)

    #
    # Get access policy
    #
    if 'accessPolicy' in form:
        access_policy = form.get('accessPolicy', '').lower()
        mlmmj_params.pop('accessPolicy')
    else:
        access_policy = 'public'

    if access_policy not in iredutils.ML_ACCESS_POLICIES:
        access_policy = 'public'

    mlmmj_params['access_policy'] = access_policy
    mlmmj_params['only_subscriber_can_post'] = 'no'
    mlmmj_params['only_moderator_can_post'] = 'no'
    if access_policy == 'membersonly':
        mlmmj_params['only_subscriber_can_post'] = 'yes'
    elif access_policy == 'moderatorsonly':
        mlmmj_params['only_moderator_can_post'] = 'yes'

    #
    # Get max message size (in bytes)
    #
    mlmmj_params['max_message_size'] = 0

    # `max_mail_size` and `max_mail_size_unit` are used by web form.
    _size = form.get('max_mail_size', 0)
    _unit = form.get('max_mail_size_unit', 'KB')
    try:
        _size = int(_size)
    except:
        pass

    if _size:
        if _unit == 'KB':
            mlmmj_params['max_message_size'] = _size * 1024
        elif _unit == 'MB':
            mlmmj_params['max_message_size'] = _size * 1024 * 1024

    if 'max_mail_size' in mlmmj_params:
        mlmmj_params.pop('max_mail_size')

    if 'max_mail_size_unit' in mlmmj_params:
        mlmmj_params.pop('max_mail_size_unit')

    # Other radio/checkbox options.
    for (k, v) in list(mlmmj_params.items()):
        # mlmmjadmin API expects values in 'yes', 'no'.
        if v == 'on':
            mlmmj_params[k] = 'yes'

        # Rename 'hidden_<key>' to '<key>'
        if k.startswith('hidden_'):
            nk = k.replace('hidden_', '')   # don't use `string.lstrip()`
            mlmmj_params.pop(k)

            if nk not in mlmmj_params:
                mlmmj_params[nk] = 'no'

    return mlmmj_params


def get_mlmmj_params_from_api(form):
    """Convert parameter names/values in API form to mlmmjadmin parameters.

    :param form: dict of web form.

    It also supports all parameters supported by mlmmjadmin.
    """
    # `kvs` stores mlmmj parameters
    kvs = form.copy()

    #
    # Get max message size (in bytes)
    #
    if 'max_message_size' in form:
        kvs['max_message_size'] = 0

        try:
            _size = abs(int(form.get('max_message_size', 0)))
            kvs['max_message_size'] = _size
        except:
            kvs.pop('max_message_size')

    return kvs
