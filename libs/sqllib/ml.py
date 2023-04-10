# Author: Zhang Huangbin <zhb@iredmail.org>

import web
from libs import iredutils, form_utils
from libs.logger import log_traceback, log_activity

from libs.sqllib import SQLWrap, decorators
from libs.sqllib import general as sql_lib_general
from libs.sqllib import domain as sql_lib_domain
from libs import mlmmj
import settings

session = web.config.get('_session')


def __is_mlid_exists(mlid, conn=None):
    """Return True if mailing list id exists."""
    mlid = str(mlid).lower()

    if not conn:
        _wrap = SQLWrap()
        conn = _wrap.conn

    try:
        qr = conn.select('maillists',
                         vars={'mlid': mlid},
                         what='mlid',
                         where='mlid=$mlid',
                         limit=1)
        if qr:
            return True
        else:
            return False
    except:
        return False


def __get_new_mlid(conn=None):
    mlid = mlmmj.generate_mlid()

    if not conn:
        _wrap = SQLWrap()
        conn = _wrap.conn

    _counter = 0
    while True:
        # Try 20 times.
        if _counter >= 20:
            raise ValueError("Cannot get an unique mailing list id after tried 20 times.")

        if not __is_mlid_exists(mlid=mlid, conn=conn):
            break
        else:
            _counter += 1
            mlid = mlmmj.generate_mlid()

    return mlid


@decorators.require_domain_access
def num_maillists_under_domain(domain, disabled_only=False, first_char=None, conn=None):
    if not iredutils.is_domain(domain):
        return 0

    num = 0
    sql_vars = {'domain': domain}

    sql_where = ''
    if disabled_only:
        sql_where = ' AND active=0'

    if first_char:
        sql_where += ' AND address LIKE %s' % web.sqlquote(first_char.lower() + '%')

    if not conn:
        _wrap = SQLWrap()
        conn = _wrap.conn

    try:
        qr = conn.select('maillists',
                         vars=sql_vars,
                         what='COUNT(address) AS total',
                         where='domain=$domain %s' % sql_where)
        num = qr[0].total or 0
    except:
        log_traceback()

    return num


def num_maillists_managed_by_user(mail, first_char=None, conn=None):
    mail = str(mail).lower()
    if not iredutils.is_email(mail):
        return 0

    num = 0
    sql_vars = {'mail': mail}

    sql_where = ''

    if first_char:
        sql_where += ' AND address LIKE %s' % web.sqlquote(first_char.lower() + '%')

    if not conn:
        _wrap = SQLWrap()
        conn = _wrap.conn

    mls = set()
    try:
        # It's possible user is moderator and owner of same list, so we need to
        # avoid duplication here, using SQL query `COUNT(*) AS total` is wrong.
        qr = conn.select('moderators',
                         vars=sql_vars,
                         what='address',
                         where='moderator=$mail %s' % sql_where)
        for i in qr:
            addr = i["address"].strip().lower()
            mls.add(addr)

        qr = conn.select('maillist_owners',
                         vars=sql_vars,
                         what='address',
                         where='owner=$mail %s' % sql_where)
        for i in qr:
            addr = i["address"].strip().lower()
            mls.add(addr)

        num = len(mls)
    except:
        log_traceback()

    return num


def get_first_char_of_all_managed_mls(mail, conn=None):
    """Get first character of managed mailing lists.

    @mail - must be a valid email address or mailing list owner or moderator.
    @conn - SQL connection cursor
    """
    if not conn:
        _wrap = SQLWrap()
        conn = _wrap.conn

    chars = []
    for tbl, col in [("moderators", "moderator"),
                     ("maillist_owners", "owner")]:
        try:
            qr = conn.select(tbl,
                             vars={'mail': mail},
                             what="SUBSTRING(address FROM 1 FOR 1) AS first_char",
                             where='{}=$mail'.format(col),
                             group='first_char')

            if qr:
                chars = [str(i.first_char).upper() for i in qr if i not in chars]
                chars.sort()
        except Exception as e:
            log_traceback()
            return False, repr(e)

    return True, chars


def get_basic_ml_profiles(domain,
                          columns=None,
                          first_char=None,
                          page=0,
                          disabled_only=False,
                          email_only=False,
                          conn=None):
    """Get all maillists under domain.

    Return data:
        (True, [{'mail': 'list@domain.com',
                 'name': '...',
                 ...other profiles in `vmail.maillists` table...
                 }])
    """
    domain = web.safestr(domain).lower()
    if not iredutils.is_domain(domain):
        raise web.seeother('/domains?msg=INVALID_DOMAIN_NAME')

    sql_vars = {'domain': domain}

    if columns:
        sql_what = ','.join(columns)
    else:
        sql_what = '*'

    if email_only:
        sql_what = 'address'

    additional_sql_where = ''
    if first_char:
        additional_sql_where = ' AND address LIKE %s' % web.sqlquote(first_char.lower() + '%')

    if disabled_only:
        additional_sql_where = ' AND active=0'

    # Get basic profiles
    try:
        if not conn:
            _wrap = SQLWrap()
            conn = _wrap.conn

        if page:
            qr = conn.select('maillists',
                             vars=sql_vars,
                             what=sql_what,
                             where='domain=$domain %s' % additional_sql_where,
                             order='address ASC',
                             limit=settings.PAGE_SIZE_LIMIT,
                             offset=(page - 1) * settings.PAGE_SIZE_LIMIT)
        else:
            qr = conn.select('maillists',
                             vars=sql_vars,
                             what=sql_what,
                             where='domain=$domain %s' % additional_sql_where,
                             order='address ASC')

        if email_only:
            emails = [i.address for i in qr]
            emails.sort()
            return True, emails
        else:
            _profiles = list(qr)
            return True, _profiles
    except Exception as e:
        return False, repr(e)


def get_basic_profiles_of_managed_mls(first_char=None, page=1, conn=None):
    """Get profile of owned/moderated mailing lists.

    Return data:
        (True, [
                {'mail': 'list@domain.com',
                 'name': '...',
                 ...other profiles in `vmail.maillists` table...
                 }
                 ])
    """
    mail = session["username"]
    if page < 1:
        page = 1

    sql_vars = {"mail": mail}
    if not conn:
        _wrap = SQLWrap()
        conn = _wrap.conn

    # Get owned / moderated mailing lists.
    mls = set()
    for tbl, col in [("maillist_owners", "owner"),
                     ("moderators", "moderator")]:
        try:
            qr = conn.select(tbl,
                             vars=sql_vars,
                             what="address",
                             where="{}=$mail".format(col))
            for i in qr:
                addr = i["address"].strip().lower()
                mls.add(addr)
        except:
            pass

    if first_char:
        char = first_char.lower()
        mls = [i for i in mls if i.startswith(char)]

    if not mls:
        return True, []

    sql_vars["mls"] = mls

    # Get basic profiles
    try:
        if page:
            qr = conn.select('maillists',
                             vars=sql_vars,
                             where="address IN $mls",
                             order='address ASC',
                             limit=settings.PAGE_SIZE_LIMIT,
                             offset=(page - 1) * settings.PAGE_SIZE_LIMIT)

        _profiles = list(qr)
        return True, _profiles
    except Exception as e:
        return False, repr(e)


@decorators.require_domain_access
def add_ml_from_web_form(domain, form, conn=None):
    """
    Add mailing list account from web from.

    :param domain: an valid domain name
    :param form: a dict of web form data
    :param conn: sql connection cursor
    """
    domain = str(domain).lower()

    # Get domain name, username, cn.
    form_domain = form_utils.get_domain_name(form)
    listname = web.safestr(form.get('listname')).strip().lower()

    if not (domain == form_domain):
        return False, 'PERMISSION_DENIED'

    if not iredutils.is_domain(domain):
        return False, 'INVALID_DOMAIN_NAME'

    mail = listname + '@' + domain
    if not iredutils.is_auth_email(mail):
        return False, 'INVALID_MAIL'

    if not conn:
        _wrap = SQLWrap()
        conn = _wrap.conn

    # Check account existing.
    if sql_lib_general.is_email_exists(mail=mail, conn=conn):
        return False, 'ALREADY_EXISTS'

    # Get domain profile.
    qr_profile = sql_lib_domain.profile(conn=conn, domain=domain)

    if qr_profile[0]:
        domain_profile = qr_profile[1]
    else:
        return qr_profile

    # Check account limit.
    num_exist = num_maillists_under_domain(conn=conn, domain=domain)

    if domain_profile.maillists == -1:
        return False, 'NOT_ALLOWED'
    elif domain_profile.maillists > 0:
        if domain_profile.maillists <= num_exist:
            return False, 'EXCEEDED_DOMAIN_ACCOUNT_LIMIT'

    try:
        mlmmj_params = form_utils.get_mlmmj_params_from_web_form(form)

        # Append relay_host
        if settings.AMAVISD_QUARANTINE_HOST:
            mlmmj_params['relay_host'] = settings.AMAVISD_QUARANTINE_HOST

        # create mlmmj account
        qr = mlmmj.create_account(mail=mail, form=mlmmj_params)
        if not qr[0]:
            return qr

        params = {
            'active': 1,
            'address': mail,
            'domain': domain,
            'name': form_utils.get_name(form=form, input_name='name'),
            'maxmsgsize': mlmmj_params['max_message_size'],
            'transport': mlmmj.generate_transport(mail),
            'mlid': __get_new_mlid(conn=conn),
            'created': iredutils.get_gmttime(),
            'accesspolicy': mlmmj_params['access_policy'],
        }

        conn.insert('maillists', **params)

        # Add a forwarding record in sql table: `vmail.forwardings`
        # it will help make things easier like avoiding multiple SQL queries
        # to check whether an email address is existing.
        params = {
            'address': mail,
            'forwarding': mail,
            'domain': domain,
            'dest_domain': domain,
            'is_maillist': 1,
            'active': 1,
        }

        conn.insert('forwardings', **params)

        log_activity(msg="Create mailing list: %s." % mail,
                     domain=domain,
                     event='create')

        # Add `postmaster@` as owner and moderator.
        for tbl, col in [("maillist_owners", "owner"),
                         ("moderators", "moderator")]:
            try:
                row = {
                    "address": mail,
                    col: "postmaster@" + domain,
                    "domain": domain,
                    "dest_domain": domain,
                }
                conn.insert(tbl, **row)
            except:
                pass

        # Add subscribers. For RESTful API.
        if 'subscribers' in form:
            _subscribers = form_utils.get_multi_values_from_api(form=form,
                                                                input_name='subscribers',
                                                                is_email=True)

            if _subscribers:
                _subscription = form.get('subscription', 'normal')

                # Store members in mlmmj.
                qr = mlmmj.add_subscribers(mail=mail,
                                           subscribers=_subscribers,
                                           subscription=_subscription,
                                           require_confirm=False)

                if not qr[0]:
                    return qr

        return True,
    except Exception as e:
        if e.__class__.__name__ == 'IntegrityError':
            return False, 'ALREADY_EXISTS'
        else:
            return False, repr(e)


def get_profile(mail, with_subscribers=False, conn=None):
    if not iredutils.is_email(mail):
        return False, 'INVALID_MAIL'

    try:
        if not conn:
            _wrap = SQLWrap()
            conn = _wrap.conn

        qr = conn.select('maillists',
                         vars={'address': mail},
                         where='address=$address')

        if qr:
            profile = list(qr)[0]

            # get mlmmj profile
            _qr = mlmmj.get_account_profile(mail=mail, with_subscribers=with_subscribers)
            if _qr[0]:
                profile.update(_qr[1])
            else:
                return _qr

            return True, profile
        else:
            return False, 'NO_SUCH_ACCOUNT'
    except Exception as e:
        return False, repr(e)


def get_profile_by_mlid(mlid, conn=None):
    if not iredutils.is_mlid(mlid):
        return False, 'INVALID_'

    try:
        if not conn:
            _wrap = SQLWrap()
            conn = _wrap.conn

        qr = conn.select('maillists',
                         vars={'mlid': mlid},
                         where='is_newsletter=1 AND mlid=$mlid AND active=1',
                         limit=1)

        if qr:
            profile = list(qr)[0]

            return True, profile
        else:
            return False, 'NO_SUCH_ACCOUNT'
    except Exception as e:
        return False, repr(e)


def get_alias_addresses(mail, conn=None):
    if not iredutils.is_email(mail):
        return False, 'INVALID_MAIL'

    if not conn:
        _wrap = SQLWrap()
        conn = _wrap.conn

    addresses = []
    try:
        qr = conn.select(
            'forwardings',
            vars={'mail': mail},
            what='address',
            where='forwarding=$mail AND is_alias=1',
        )

        for row in qr:
            addresses.append(str(row['address']).lower())

        addresses.sort()
        return True, addresses
    except Exception as e:
        return False, repr(e)


def update(mail, profile_type, form, conn=None):
    mail = web.safestr(mail).lower()
    domain = mail.split('@', 1)[-1]

    if not iredutils.is_email(mail):
        return False, 'INVALID_MAIL'

    if not conn:
        _wrap = SQLWrap()
        conn = _wrap.conn

    mlmmj_params = form_utils.get_mlmmj_params_from_web_form(form)

    params = {}
    if profile_type == 'general':
        params['name'] = form.get('name', '')
        params['accesspolicy'] = mlmmj_params['access_policy']
        params['maxmsgsize'] = mlmmj_params['max_message_size']

        # Do not allow mailing list owner / moderator to enable/disable list.
        if session.get('is_global_admin') or session.get('is_normal_admin'):
            params['active'] = 0
            if 'accountStatus' in form:
                # Enabled.
                params['active'] = 1

        params['modified'] = iredutils.get_gmttime()

        try:
            # Update profile
            conn.update('maillists',
                        vars={'address': mail},
                        where='address=$address',
                        **params)

            # Do not allow mailing list owner / moderator to enable/disable list.
            if session.get('is_global_admin') or session.get('is_normal_admin'):
                conn.update('forwardings',
                            vars={'address': mail},
                            where='address=$address',
                            active=params['active'])

            qr = mlmmj.update_account_profile(mail=mail, data=mlmmj_params)
            if not qr[0]:
                return qr

            # Log changes.
            msg = "Update maillist profile (%s)." % mail
            log_activity(msg=msg, username=mail, domain=domain, event='update')
        except Exception as e:
            return False, repr(e)

    elif profile_type == 'aliases':
        # Do not allow mailing list owner / moderator to enable/disable list.
        if not (session.get('is_global_admin') or session.get('is_normal_admin')):
            return False, "PERMISSION_DENIED"

        # Per-account alias addresses.
        alias_addresses = form_utils.get_multi_values_from_textarea(
            form=form,
            input_name='account_alias_addresses',
            is_email=True,
            to_lowercase=True,
        )

        # Delete all existing per-account alias addresses first.
        conn.delete('forwardings',
                    vars={'mail': mail},
                    where='forwarding=$mail AND is_alias=1')

        alias_addresses = [i for i in alias_addresses if i.split('@', 1)[-1] == domain]

        if not alias_addresses:
            return True,

        qr = sql_lib_general.filter_existing_emails(mails=alias_addresses, conn=conn)
        alias_addresses = qr['nonexist']
        if not alias_addresses:
            return True,

        rows = []
        for addr in alias_addresses:
            row = {
                'address': addr,
                'forwarding': mail,
                'domain': addr.split('@', 1)[-1],
                'dest_domain': domain,
                'is_alias': 1,
            }

            rows.append(row)

        conn.multiple_insert('forwardings', rows)
    elif profile_type == 'members':
        action = form.get('action')

        if action == 'remove':
            # Remove members
            try:
                subscribers = [str(i).strip().lower()
                               for i in form.get('subscriber', [])
                               if iredutils.is_email(i)]
                if subscribers:
                    qr = mlmmj.remove_subscribers(mail=mail, subscribers=subscribers)
                    if not qr[0]:
                        return qr
            except Exception as e:
                return False, repr(e)
        elif action == 'remove_all':
            # Remove all members from mlmmj.
            qr = mlmmj.remove_all_subscribers(mail=mail)
            if not qr[0]:
                return qr

    elif profile_type == 'owners':
        # Do not allow mailing list owner / moderator to update owner/moderators.
        if not (session.get('is_global_admin') or session.get('is_normal_admin')):
            return False, "PERMISSION_DENIED"

        kvs = {}
        for k in ['owners', 'moderators', 'subscription_moderators']:
            _addresses = form_utils.get_multi_values(form=form,
                                                     input_name=k,
                                                     default_value='',
                                                     input_is_textarea=True,
                                                     is_email=True,
                                                     to_lowercase=True,
                                                     to_string=True)

            if mail in _addresses:
                _addresses.remove(mail)

            kvs[k] = list(set(_addresses))

        # Remove non-exist accounts under same domain
        _addresses_in_domain = set()
        for _values in list(kvs.values()):
            _addrs = [i for i in _values if i.endswith('@' + domain)]
            _addresses_in_domain.update(_addrs)

        qr = sql_lib_general.filter_existing_emails(mails=_addresses_in_domain, conn=conn)
        _exists = qr['exist']

        for (k, v) in list(kvs.items()):
            _ext = [i for i in v if not i.endswith('@' + domain)]
            _int = [i for i in v if i.endswith('@' + domain) and i in _exists]

            kvs[k] = ', '.join(_ext + _int)

        kvs['moderate_subscription'] = mlmmj_params.get('moderate_subscription')

        qr = mlmmj.update_account_profile(mail=mail, data=kvs)
        if not qr[0]:
            return qr

        # Store owners and moderators in SQL db.
        #      [(<key in `kvs`>, <sql table name>, <column name>), ...]
        for k, tbl, col in [("moderators", "moderators", "moderator"),
                            ("owners", "maillist_owners", "owner")]:
            try:
                conn.delete(tbl,
                            vars={'address': mail},
                            where='address=$address')

                if kvs[k]:
                    _addresses = kvs[k].split(',')
                    _addresses = [i.strip().lower() for i in _addresses if iredutils.is_email(i)]

                    records = []
                    for _addr in _addresses:
                        params = {
                            'address': mail,
                            col: _addr,
                            'domain': domain,
                            'dest_domain': _addr.split('@', 1)[-1],
                        }

                        records.append(params)

                    conn.multiple_insert(tbl, records)
            except Exception as e:
                return False, repr(e)

            # Log changes.
            for k in kvs:
                msg = "Update maillist {} ({}): {}".format(k, mail, kvs[k])
                log_activity(msg=msg, username=mail, domain=domain, event='update')

    elif profile_type == 'newsletter':
        params['is_newsletter'] = 0
        if 'is_newsletter' in form:
            params['is_newsletter'] = 1

        params['description'] = form_utils.get_single_value(form=form, input_name='description')

        try:
            conn.update('maillists',
                        vars={'address': mail},
                        where='address=$address',
                        **params)
        except Exception as e:
            return False, repr(e)

    return True,


def delete_maillists(accounts, keep_archive=True, conn=None):
    """Delete mailing lists under same domain."""
    if not accounts:
        return True,

    # Get domain from first account
    domain = accounts[0].split('@', 1)[-1]
    if not iredutils.is_domain(domain):
        return True,

    sql_vars = {'domain': domain, 'accounts': accounts}

    try:
        if not conn:
            _wrap = SQLWrap()
            conn = _wrap.conn

        for tbl in ['maillists', 'maillist_owners']:
            conn.delete(tbl,
                        vars=sql_vars,
                        where='address IN $accounts')

        conn.delete('forwardings',
                    vars=sql_vars,
                    where='address IN $accounts OR forwarding IN $accounts')

        log_activity(event='delete',
                     domain=accounts[0].split('@', 1)[-1],
                     msg="Delete mailing lists: %s." % ', '.join(accounts))
    except Exception as e:
        return False, repr(e)

    # Remove mailing list from domain.settings: default_groups
    qr = sql_lib_domain.remove_default_maillists_in_domain_setting(
        domain=domain,
        maillists=accounts,
        conn=conn,
    )

    if not qr[0]:
        return qr

    # Remove mlmmj accounts
    qr = mlmmj.delete_accounts(mails=accounts, keep_archive=keep_archive)
    if not qr[0]:
        return qr

    return True,


def get_subscribers(mail, email_only=False):
    mail = str(mail).lower()
    if not iredutils.is_email(mail):
        return False, 'INVALID_EMAIL'

    qr = mlmmj.get_subscribers(mail=mail, email_only=email_only)
    return qr


def add_subscribers(mail, form, conn=None):
    mail = str(mail).lower()
    domain = mail.split('@', 1)[-1]
    if not iredutils.is_email(mail):
        return False, 'INVALID_EMAIL'

    if not conn:
        _wrap = SQLWrap()
        conn = _wrap.conn

    if not sql_lib_general.is_ml_exists(mail=mail, conn=conn):
        return False, 'INVALID_EMAIL'

    _subscription = form.get('subscription', 'normal')
    _subscribers = form_utils.get_multi_values(form=form,
                                               input_name='new_subscribers',
                                               default_value='',
                                               input_is_textarea=True,
                                               is_email=True,
                                               to_lowercase=True,
                                               to_string=False)

    _internal_subs = {i for i in _subscribers if i.endswith('@' + domain)}
    _subscribers = {i for i in _subscribers if not i.endswith('@' + domain)}

    _qr = sql_lib_general.filter_existing_emails(mails=_internal_subs, conn=None)
    _internal_subs = _qr['exist']
    _subscribers.update(_internal_subs)

    qr = mlmmj.add_subscribers(mail=mail,
                               subscribers=_subscribers,
                               subscription=_subscription)
    return qr


def migrate_alias_to_ml(mail, conn=None):
    """Migrate mail alias account to subscribable mlmmj mailing list."""
    mail = mail.lower()
    (listname, domain) = mail.split('@', 1)

    if not conn:
        _wrap = SQLWrap()
        conn = _wrap.conn

    sql_vars = {'mail': mail}

    # Get profile of old alias account
    qr = conn.select('alias',
                     vars=sql_vars,
                     where='address=$mail',
                     limit=1)
    if not qr:
        return False, 'INVALID_MAIL'

    profile_alias = list(qr)[0]

    #
    # Create mlmmj account
    #
    params = {
        'mail': mail,
        'subject_prefix': '[%s]' % listname,
    }

    # access policy
    access_policy = profile_alias.get('accesspolicy', '')
    if access_policy == 'membersonly':
        params['only_subscriber_can_post'] = 'yes'
        params['only_moderator_can_post'] = 'no'
    elif access_policy in ['moderatorsonly', 'allowedonly']:
        params['only_subscriber_can_post'] = 'no'
        params['only_moderator_can_post'] = 'yes'

    # Disable subscription/unsubscription by default
    params['close_list'] = 'yes'

    # Use postmaster@ as default owner
    params['owner'] = 'postmaster@' + domain

    # Append relay_host
    if settings.AMAVISD_QUARANTINE_HOST:
        params['relay_host'] = settings.AMAVISD_QUARANTINE_HOST

    qr = mlmmj.create_account(mail=mail, form=params)
    if not qr[0]:
        return qr

    # Migrate members.
    qr = conn.select('forwardings',
                     vars=sql_vars,
                     where='address=$mail',
                     what='forwarding')
    members = set()
    for i in qr:
        members.add(str(i.forwarding).strip().lower())

    if members:
        qr = mlmmj.add_subscribers(mail=mail,
                                   subscribers=members,
                                   subscription='normal',
                                   require_confirm=False)
        if not qr[0]:
            return qr

    del members

    # Migrate moderators.
    # Note: No need to update sql records of moderators.
    qr = conn.select('moderators',
                     vars=sql_vars,
                     where='address=$mail',
                     what='moderator')
    moderators = set()
    for i in qr:
        moderators.add(str(i.moderator).lower())

    if moderators:
        qr = mlmmj.update_account_profile(mail=mail, data={'moderators': ','.join(moderators)})
        if not qr[0]:
            return qr

    del moderators

    # Create new mailing list account in SQL
    param = {
        'address': mail,
        'domain': domain,
        'name': profile_alias.get('name', ''),
        'active': profile_alias.get('active', 1),
        'accesspolicy': access_policy,
        'mlid': __get_new_mlid(conn=conn),
        'transport': mlmmj.generate_transport(mail),
    }

    try:
        conn.insert('maillists', **param)

        # Delete all records with `address=<mail>`.
        # List members are stored in mlmmj data directory.
        conn.delete('forwardings',
                    vars=sql_vars,
                    where='address=$mail')

        conn.insert('forwardings',
                    address=mail,
                    forwarding=mail,
                    domain=domain,
                    dest_domain=domain,
                    is_maillist=1,
                    is_list=0,
                    is_forwarding=0,
                    is_alias=0)

    except Exception as e:
        return False, repr(e)

    # remove old alias account
    try:
        conn.delete('alias',
                    vars={'mail': mail},
                    where='address=$mail')

        return True,
    except Exception as e:
        return False, repr(e)


@decorators.require_domain_access
def api_update_profile(mail, form, conn=None):
    mail = web.safestr(mail).lower()
    domain = mail.split('@', 1)[-1]

    if not iredutils.is_email(mail):
        return False, 'INVALID_MAIL'

    if not conn:
        _wrap = SQLWrap()
        conn = _wrap.conn

    # Parameters stored in SQL db.
    kvs = {}

    # Name
    kv = form_utils.get_form_dict(form=form, input_name='name')
    kvs.update(kv)

    # Account status
    _account_status = form_utils.get_account_status(form=form,
                                                    input_name='accountStatus',
                                                    default_value='active',
                                                    to_integer=True)
    if _account_status in [1, 0]:
        kvs['active'] = _account_status

    # Max message size
    kv = form_utils.get_form_dict(form=form, input_name='max_message_size', key_name='maxmsgsize')
    kvs.update(kv)

    # Get access policy
    if 'accessPolicy' in form:
        _policy = form_utils.get_single_value(form=form,
                                              input_name='accessPolicy',
                                              to_string=True,
                                              to_lowercase=True)

        if _policy == 'membersonly':
            form['only_subscriber_can_post'] = 'yes'
            form['only_moderator_can_post'] = 'no'
        elif _policy in ['moderatorsonly', 'allowedonly']:
            form['only_subscriber_can_post'] = 'no'
            form['only_moderator_can_post'] = 'yes'
        else:
            if _policy in iredutils.ML_ACCESS_POLICIES:
                form['only_subscriber_can_post'] = 'no'
                form['only_moderator_can_post'] = 'no'

                kvs['accesspolicy'] = _policy

    # Although below two parameters maybe set by 'Get access policy' section,
    # we still need to handle the ones posted from client directly.
    if 'only_moderator_can_post' in form:
        if form.get('only_moderator_can_post', 'no') == 'yes':
            kvs['accesspolicy'] = 'moderatorsonly'
    elif 'only_subscriber_can_post' in form:
        if form.get('only_subscriber_can_post', 'no') == 'yes':
            kvs['accesspolicy'] = 'membersonly'

    # Newsletter
    if 'is_newsletter' in form:
        if form.get('is_newsletter') == 'yes':
            kvs['is_newsletter'] = 1
        else:
            kvs['is_newsletter'] = 0

    kv = form_utils.get_form_dict(form=form, input_name='newsletter_description', key_name='description')
    kvs.update(kv)

    # Store moderators/owners in SQL db.
    #      [(<key in `kvs`>, <sql table name>, <column name>), ...]
    for k, tbl, col in [("moderators", "moderators", "moderator"),
                        ("owners", "maillist_owners", "owner")]:
        if k in form:
            _addresses = form_utils.get_multi_values_from_api(form=form,
                                                              input_name=k,
                                                              is_email=True)

            # Remove duplicate addresses.
            _addresses = list(set(_addresses))

            # Remove self
            if mail in _addresses:
                _addresses.remove(mail)

            # Delete existing moderators first.
            try:
                conn.delete(tbl,
                            vars={'address': mail},
                            where='address=$address')
            except Exception as e:
                return False, repr(e)

            if _addresses:
                # Store moderators in SQL
                records = []
                for _addr in _addresses:
                    params = {
                        'address': mail,
                        col: _addr,
                        'domain': domain,
                        'dest_domain': _addr.split('@', 1)[-1],
                    }

                    records.append(params)

                try:
                    conn.multiple_insert(tbl, records)

                    # Log changes.
                    msg = "Reset mailing list ({}) {} to: {}".format(mail, k, ', '.join(_addresses))
                    log_activity(msg=msg, username=mail, domain=domain, event='update')
                except Exception as e:
                    return False, repr(e)

    try:
        kvs['modified'] = iredutils.get_gmttime()

        # Update profile
        conn.update('maillists',
                    vars={'address': mail},
                    where='address=$address',
                    **kvs)

        conn.update('forwardings',
                    vars={'address': mail},
                    where='address=$address',
                    active=kvs['active'])

        # Log changes.
        msg = "Update maillist profile (%s)." % mail
        log_activity(msg=msg, username=mail, domain=domain, event='update')
    except Exception as e:
        return False, repr(e)

    mlmmj_params = form_utils.get_mlmmj_params_from_api(form=form)
    qr = mlmmj.update_account_profile(mail=mail, data=mlmmj_params)
    if not qr[0]:
        return qr

    # Add/remove subscribers
    if 'add_subscribers' in form:
        _subscribers = form_utils.get_multi_values_from_api(form=form,
                                                            input_name='add_subscribers',
                                                            is_email=True)

        if _subscribers:
            _subscription = form.get('subscription', 'normal')
            _require_confirm = (form.get('require_confirm') == "yes")

            qr = mlmmj.add_subscribers(mail=mail,
                                       subscribers=_subscribers,
                                       subscription=_subscription,
                                       require_confirm=_require_confirm)

            if not qr[0]:
                return qr

    if 'remove_subscribers' in form:
        _subscribers = form_utils.get_multi_values_from_api(form=form,
                                                            input_name='remove_subscribers',
                                                            is_email=True)

        if _subscribers:
            qr = mlmmj.remove_subscribers(mail=mail, subscribers=_subscribers)
            if not qr[0]:
                return qr

    return True,
