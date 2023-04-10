# Author: Zhang Huangbin <zhb@iredmail.org>

import web
import settings
from libs import iredutils, form_utils

from libs.logger import logger, log_activity
from libs.sqllib import SQLWrap, decorators
from libs.sqllib import general as sql_lib_general
from libs.sqllib import domain as sql_lib_domain

session = web.config.get('_session')


@decorators.require_domain_access
def change_email(mail, new_mail, conn=None):
    if not iredutils.is_email(mail):
        return False, 'INVALID_OLD_EMAIL'

    if not iredutils.is_email(new_mail):
        return False, 'INVALID_NEW_EMAIL'

    old_domain = mail.split('@', 1)[-1]
    new_domain = new_mail.split('@', 1)[-1]

    if old_domain != new_domain:
        return False, 'PERMISSION_DENIED'

    if not conn:
        _wrap = SQLWrap()
        conn = _wrap.conn

    if not sql_lib_general.is_email_exists(mail=mail, conn=conn):
        return False, 'OLD_EMAIL_NOT_EXIST'

    if sql_lib_general.is_email_exists(mail=new_mail, conn=conn):
        return False, 'NEW_EMAIL_ALREADY_EXISTS'

    # Change email address
    try:
        sql_vars = {'mail': mail, 'new_mail': new_mail}

        conn.update('alias',
                    vars=sql_vars,
                    address=new_mail,
                    where='address=$mail')

        # Update per-user mail forwardings, alias memberships
        conn.update('forwardings',
                    vars=sql_vars,
                    address=new_mail,
                    where='address=$mail')

        conn.update('forwardings',
                    vars=sql_vars,
                    forwarding=new_mail,
                    where='forwarding=$mail')

        # Update moderators
        conn.update('moderators',
                    vars=sql_vars,
                    address=new_mail,
                    where='address=$mail')

        conn.update('moderators',
                    vars=sql_vars,
                    moderator=new_mail,
                    where='moderator=$mail')

        log_activity(event='update',
                     domain=old_domain,
                     msg="Change alias account email address: {} -> {}.".format(mail, new_mail))

        return True,
    except Exception as e:
        return False, repr(e)


def add_alias_from_form(domain, form, conn=None):
    # Get domain name, username, cn.
    form_domain = form_utils.get_domain_name(form)
    username = web.safestr(form.get('listname')).strip().lower()
    mail = username + '@' + form_domain

    if domain != form_domain:
        return False, 'PERMISSION_DENIED'

    if not iredutils.is_domain(domain):
        return False, 'INVALID_DOMAIN_NAME'

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
    num_exist = num_aliases_under_domain(conn=conn, domain=domain)

    if domain_profile.aliases == -1:
        return False, 'NOT_ALLOWED'
    elif domain_profile.aliases > 0:
        if domain_profile.aliases <= num_exist:
            return False, 'EXCEEDED_DOMAIN_ACCOUNT_LIMIT'

    # Define columns and values used to insert.
    columns = {
        'address': mail, 'domain': domain,
        'name': form_utils.get_name(form=form),
        'created': iredutils.get_gmttime(), 'active': 1,
        'accesspolicy': form_utils.get_list_access_policy(form=form,
                                                          input_name='accessPolicy',
                                                          default_value='public'),
    }

    # Get access policy

    try:
        conn.insert('alias', **columns)

        log_activity(msg="Create mail alias: %s." % mail,
                     domain=domain,
                     event='create')
        return True,
    except Exception as e:
        return False, repr(e)


def delete_aliases(accounts, conn=None):
    """Delete alias accounts under same domain."""
    accounts = [str(i).lower() for i in accounts if iredutils.is_email(i)]
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

        conn.delete('alias',
                    vars=sql_vars,
                    where='address IN $accounts')

        conn.delete('forwardings',
                    vars=sql_vars,
                    where='address IN $accounts OR forwarding IN $accounts')

        log_activity(event='delete',
                     domain=accounts[0].split('@', 1)[-1],
                     msg="Delete alias: %s." % ', '.join(accounts))
    except Exception as e:
        return False, repr(e)

    # Remove alias from domain.settings: default_groups
    qr = sql_lib_domain.remove_default_maillists_in_domain_setting(domain=domain,
                                                                   maillists=accounts,
                                                                   conn=conn)
    if not qr[0]:
        return qr

    return True,


@decorators.require_domain_access
def num_aliases_under_domain(conn, domain, disabled_only=False, first_char=None):
    if not iredutils.is_domain(domain):
        return False, 'INVALID_DOMAIN_NAME'

    num = 0
    sql_vars = {'domain': domain}

    sql_where = ''
    if disabled_only:
        sql_where = ' AND active=0'

    if first_char:
        sql_where += ' AND address LIKE %s' % web.sqlquote(first_char.lower() + '%')

    try:
        qr = conn.select('alias',
                         vars=sql_vars,
                         what='COUNT(address) AS total',
                         where='domain=$domain %s' % sql_where)
        num = qr[0].total or 0
    except:
        pass

    return num


@decorators.require_domain_access
def get_basic_alias_profiles(domain,
                             columns=None,
                             first_char=None,
                             page=0,
                             email_only=False,
                             disabled_only=False,
                             conn=None):
    """Get all aliases under domain.

    Return data:
        (True, [{'mail': 'alias@domain.com',
                 'name': '...',
                 ...other profiles in `vmail.alias` table...
                 'members', [...],
                 'moderators', [...]]
    """
    domain = web.safestr(domain).lower()
    if not iredutils.is_domain(domain):
        raise web.seeother('/domains?msg=INVALID_DOMAIN_NAME')

    sql_vars = {'domain': domain}

    if columns:
        sql_what = ','.join(columns)
    else:
        if email_only:
            sql_what = 'address'
        else:
            sql_what = '*'

    # Get alias members
    additional_sql_where = ''
    if first_char:
        additional_sql_where = ' AND address LIKE %s' % web.sqlquote(first_char.lower() + '%')

    if disabled_only:
        additional_sql_where = ' AND active=0'

    # Get basic alias profiles first
    try:
        if not conn:
            _wrap = SQLWrap()
            conn = _wrap.conn

        if page:
            qr = conn.select('alias',
                             vars=sql_vars,
                             what=sql_what,
                             where='domain=$domain %s' % additional_sql_where,
                             order='address ASC',
                             limit=settings.PAGE_SIZE_LIMIT,
                             offset=(page - 1) * settings.PAGE_SIZE_LIMIT)
        else:
            qr = conn.select('alias',
                             vars=sql_vars,
                             what=sql_what,
                             where='domain=$domain %s' % additional_sql_where,
                             order='address ASC')

        if email_only:
            emails = []
            for r in qr:
                email = str(r.address).lower()
                emails.append(email)

            emails.sort()
            return True, emails
        else:
            return True, list(qr)
    except Exception as e:
        return False, repr(e)


@decorators.require_domain_access
def get_profile(mail,
                with_members=True,
                with_moderators=True,
                conn=None):
    if not iredutils.is_email(mail):
        return False, 'INVALID_MAIL'

    try:
        if not conn:
            _wrap = SQLWrap()
            conn = _wrap.conn

        qr = conn.select('alias',
                         vars={'address': mail},
                         where='address=$address',
                         limit=1)

        if qr:
            profile = list(qr)[0]

            if with_members:
                _qr = get_member_emails(mail=mail, conn=conn)
                if _qr[0]:
                    profile['members'] = _qr[1]
                    profile['members'].sort()
                else:
                    return _qr

            if with_moderators:
                _qr = get_moderators(mail=mail, conn=conn)
                if _qr[0]:
                    profile['moderators'] = _qr[1]
                    profile['moderators'].sort()
                else:
                    return _qr

            return True, profile
        else:
            return False, 'NO_SUCH_ACCOUNT'
    except Exception as e:
        return False, repr(e)


@decorators.require_domain_access
def update(mail, profile_type, form, conn=None):
    mail = web.safestr(mail).lower()
    domain = mail.split('@', 1)[-1]

    if not iredutils.is_email(mail):
        return False, 'INVALID_MAIL'

    if not conn:
        _wrap = SQLWrap()
        conn = _wrap.conn

    # change email address
    if profile_type == 'rename':
        # new email address
        new_mail = web.safestr(form.get('new_mail_username')).strip().lower() + '@' + domain
        qr = change_email(mail=mail, new_mail=new_mail, conn=conn)
        if qr[0]:
            raise web.seeother('/profile/alias/general/%s?msg=EMAIL_CHANGED' % new_mail)
        else:
            raise web.seeother('/profile/alias/general/{}?msg={}'.format(new_mail, web.urlquote(qr[1])))

    # Pre-defined.
    values = {'modified': iredutils.get_gmttime()}

    # Get cn.
    cn = form.get('cn', '')
    values['name'] = cn

    # check account status.
    values['active'] = 0
    if 'accountStatus' in form:
        # Enabled.
        values['active'] = 1

    # Get access policy.
    access_policy = str(form.get('accessPolicy'))
    if access_policy in iredutils.MAILLIST_ACCESS_POLICIES:
        values['accesspolicy'] = access_policy

    # Get members & moderators from web form.
    _members = form_utils.get_multi_values_from_textarea(form=form,
                                                         input_name='members',
                                                         is_email=True)

    _members = list({iredutils.lower_email_with_upper_ext_address(v) for v in _members})

    _moderators = [str(v).strip().lower() for v in form.get('moderators', '').splitlines()]
    _moderators = list({iredutils.lower_email_with_upper_ext_address(v)
                        for v in _moderators
                        if iredutils.is_email(v) or v.startswith('*@')})
    _moderators_wildcard = [v for v in _moderators if iredutils.is_domain(v.split('@', 1)[-1])]

    # Remove non-exist accounts in same domain.
    # Get members & moderators which in same domain.
    _members_in_domain = [i for i in _members if i.endswith('@' + domain)]
    _members_not_in_domain = [i for i in _members if not i.endswith('@' + domain)]
    _moderators_in_domain = [i for i in _moderators if i.endswith('@' + domain) and i not in _moderators_wildcard]
    _moderators_not_in_domain = [i for i in _moderators if not (i.endswith('@' + domain) or i in _moderators_wildcard)]

    # Verify internal users
    addresses_in_domain = []
    _addresses_in_domain = list(set(_members_in_domain + _moderators_in_domain))
    if _addresses_in_domain:
        try:
            # Remove non-existing addresses
            _qr = sql_lib_general.filter_existing_emails(mails=_addresses_in_domain, conn=conn)
            addresses_in_domain = _qr['exist']
        except Exception as e:
            logger.error(e)

    members_in_domain = [v for v in _members_in_domain if v in addresses_in_domain]
    moderators_in_domain = [v for v in _moderators_in_domain if v in addresses_in_domain]

    try:
        # Update profile
        conn.update('alias',
                    vars={'address': mail},
                    where='address=$address',
                    **values)

        # Delete all members and moderators first
        conn.delete('forwardings',
                    vars={'address': mail},
                    where='address=$address')

        conn.delete('moderators',
                    vars={'address': mail},
                    where='address=$address')

        # Add members by inserting new records
        _all_members = members_in_domain + _members_not_in_domain
        if _all_members:
            v = []
            for _member in _all_members:
                v += [{'address': mail,
                       'forwarding': _member,
                       'domain': domain,
                       'dest_domain': _member.split('@', 1)[-1],
                       'active': values['active'],
                       'is_list': 1}]

            conn.multiple_insert('forwardings', values=v)

        # Add moderators by inserting new records
        _all_moderators = moderators_in_domain + _moderators_not_in_domain + _moderators_wildcard
        if _all_moderators:
            v = []
            for _moderator in _all_moderators:
                v += [{'address': mail,
                       'moderator': _moderator,
                       'domain': domain,
                       'dest_domain': _moderator.split('@', 1)[-1]}]

            conn.multiple_insert('moderators', values=v)

        # Log changes.
        msg = "Update alias profile (%s)." % mail

        if access_policy:
            msg += " Access policy: %s." % access_policy

        if _all_members:
            msg += " Members: %s." % (', '.join(_all_members))
        else:
            msg += " No members."

        if _all_moderators:
            msg += " Moderators: %s." % (', '.join(_all_moderators))
        else:
            msg += " No moderators."

        log_activity(msg=msg, username=mail, domain=domain, event='update')

        return True,
    except Exception as e:
        return False, repr(e)


def get_member_emails(mail, conn=None):
    """Get members of mail alias account. Return a list of mail addresses.

    Return a list with all members' email addresses."""
    if not conn:
        _wrap = SQLWrap()
        conn = _wrap.conn

    try:
        qr = conn.select(
            'forwardings',
            vars={'mail': mail},
            what='forwarding',
            where='address=$mail AND is_list=1',
        )

        _addresses = [iredutils.lower_email_with_upper_ext_address(i.forwarding)
                      for i in qr if iredutils.is_email(i.forwarding)]
        _addresses.sort()

        return True, _addresses
    except Exception as e:
        return False, repr(e)


def get_moderators(mail, conn=None):
    """Get moderators of given mail alias account.

    Return a list with all moderators' email addresses."""
    if not conn:
        _wrap = SQLWrap()
        conn = _wrap.conn

    try:
        qr = conn.select('moderators',
                         vars={'mail': mail},
                         what='moderator',
                         where='address=$mail')

        _addresses = [iredutils.lower_email_with_upper_ext_address(i.moderator)
                      for i in qr
                      if iredutils.is_email(i.moderator) or i.moderator.startswith('*@')]
        _addresses.sort()

        return True, _addresses
    except Exception as e:
        return False, repr(e)


def reset_members(mail, members, conn=None):
    """Assign all given addresses specified in `@members` as members."""
    _addresses = {iredutils.lower_email_with_upper_ext_address(i)
                  for i in members
                  if iredutils.is_email(i)}

    domain = mail.split('@', 1)[-1]

    _addresses_in_domain = [v for v in _addresses if v.endswith('@' + domain) and v != mail]
    _addresses_not_in_domain = [v for v in _addresses if not v.endswith('@' + domain)]
    del _addresses

    if not conn:
        _wrap = SQLWrap()
        conn = _wrap.conn

    # Verify existence of addresses in same domain
    if _addresses_in_domain:
        try:
            # Remove non-existing addresses
            qr = sql_lib_general.filter_existing_emails(mails=_addresses_in_domain, conn=conn)
            _addresses_in_domain = qr['exist']
        except Exception as e:
            logger.error(e)

    try:
        # Delete all existing members first
        conn.delete('forwardings',
                    vars={'mail': mail},
                    where='address=$mail AND is_list=1')

        # Add member by inserting new record
        _all_addresses = _addresses_in_domain + _addresses_not_in_domain
        if _all_addresses:
            v = []
            for i in _all_addresses:
                v += [{'address': mail,
                       'forwarding': i,
                       'domain': domain,
                       'dest_domain': i.split('@', 1)[-1],
                       'is_list': 1}]

            conn.multiple_insert('forwardings', values=v)

        log_activity(msg='Reset alias ({}) members to: {}'.format(mail, ', '.join(_all_addresses)),
                     admin=session.get('username'),
                     username=mail,
                     domain=domain,
                     event='update')

        return True,
    except Exception as e:
        return False, repr(e)


def update_members(mail,
                   new_members=None,
                   removed_members=None,
                   conn=None):
    """Add new members to mail alias account, and remove removed_members."""
    _new = []
    if new_members:
        _new = [iredutils.lower_email_with_upper_ext_address(i)
                for i in new_members if iredutils.is_email(i)]

    _removed = []
    if removed_members:
        _removed = [iredutils.lower_email_with_upper_ext_address(i)
                    for i in removed_members if iredutils.is_email(i)]

    if not (_new or _removed):
        return True, 'NO_VALID_MEMBERS'

    domain = mail.split('@', 1)[-1]

    if not conn:
        _wrap = SQLWrap()
        conn = _wrap.conn

    # Verify existence of addresses in same domain
    _new_in_domain = set()
    _new_not_in_domain = set()
    if _new:
        for i in _new:
            if i.endswith('@' + domain):
                _new_in_domain.add(i)
            else:
                _new_not_in_domain.add(i)

        # remove self
        _new_in_domain.discard(mail)

        if _new_in_domain:
            try:
                # Remove non-existing addresses
                qr = sql_lib_general.filter_existing_emails(mails=_new_in_domain, conn=conn)
                _new_in_domain = qr['exist']
            except Exception as e:
                logger.error(e)

    # Get existing members
    qr = get_member_emails(mail=mail, conn=conn)
    if qr[0]:
        _old_members = qr[1]
    else:
        return qr

    # Add new, remove removed
    _members = set(_old_members)
    _members.update(_new_in_domain)
    _members.update(_new_not_in_domain)
    _members -= set(_removed)

    try:
        # Delete all existing members first
        conn.delete('forwardings',
                    vars={'mail': mail},
                    where='address=$mail AND is_list=1')

        # Add member by inserting new record
        if _members:
            v = []
            for i in _members:
                v += [{'address': mail,
                       'forwarding': i,
                       'domain': domain,
                       'dest_domain': i.split('@', 1)[-1],
                       'is_list': 1}]

            conn.multiple_insert('forwardings', values=v)

        log_activity(msg='Update alias ({}) members to: {}'.format(mail, ', '.join(_members)),
                     admin=session.get('username'),
                     username=mail,
                     domain=domain,
                     event='update')

        return True,
    except Exception as e:
        return False, repr(e)
