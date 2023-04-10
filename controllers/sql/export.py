# Author: Zhang Huangbin <zhb@iredmail.org>

import zipfile
import io
import csv
import web

from libs.sqllib import SQLWrap, decorators
from libs.sqllib import general as sql_lib_general
from libs.sqllib import admin as sql_lib_admin

session = web.config.get('_session')


class ExportManagedAccounts:
    @decorators.require_admin_login
    def GET(self, mail):
        mail = mail.lower()

        # Raise error if normal admin is trying to export accounts managed by
        # other admin
        if (not session.get('is_global_admin')) and session.get('username') != mail:
            raise web.seeother('/domains?msg=PERMISSION_DENIED')

        qr = sql_lib_general.export_managed_accounts(mail=mail, domains=None, conn=None)
        if not qr[0]:
            raise web.seeother('/domains?msg=%s' % web.urlquote(qr[1]))

        managed_domains = qr[1]

        # Generate summary
        content_summary = ['Accounts managed by admin: {}'.format(mail), '------']

        _domains = []
        _total_domains = 0
        _total_users = 0
        _total_lists = 0
        _total_aliases = 0

        for d in managed_domains:
            _total_domains += 1
            _domains += [d['domain']]
            _total_users += d['total_users']
            _total_lists += d['total_lists']
            _total_aliases += d['total_aliases']

        content_summary += ['- Domains: {}'.format(_total_domains)]
        content_summary += ['- Mailboxes: {}'.format(_total_users)]
        content_summary += ['- Mailing lists: {}'.format(_total_lists)]
        content_summary += ['- Mail aliases: {}'.format(_total_aliases)]

        # Generate zip file
        f = io.BytesIO()
        try:
            zf = zipfile.ZipFile(f, mode='w', compression=zipfile.ZIP_DEFLATED)
            # Summary of all managed accounts
            zf.writestr('summary.txt', '\n'.join(content_summary))

            _content_domains = ['# Exported domains:']
            _content_domains += ['# Format: domain name, display name']

            # Generate files for each domain
            for d in managed_domains:
                _domain = d['domain']
                _content_domains += ['{domain}, {name}'.format(**d)]

                for _account_type in ['users', 'lists', 'aliases']:
                    if d['total_' + _account_type] == 0:
                        continue

                    if _account_type == 'users':
                        _content = ['# Mailboxes under domain %s' % _domain]
                    elif _account_type == 'lists':
                        _content = ['# Mailing lists under domain %s' % _domain]
                    else:
                        # account_type == 'aliases'
                        _content = ['# Mail aliases under domain %s' % _domain]

                    _content += ['# Format: mail address, display name']

                    for _account in d[_account_type]:
                        _content += ['{mail}, {name}'.format(**_account)]

                    zf.writestr(_domain + '_' + _account_type + '.txt', '\n'.join(_content))

            zf.writestr('domains.txt', '\n'.join(_content_domains))
        except Exception as e:
            raise web.seeother('/domains?msg=%s' % web.urlquote(repr(e)))
        finally:
            zf.close()

        web.header('Content-Disposition', 'attachment; filename=accounts.zip')
        return f.getvalue()


class ExportDomainAccounts:
    @decorators.require_admin_login
    def GET(self, domain):
        domain = str(domain).lower()
        mail = session.get('username')

        _wrap = SQLWrap()
        conn = _wrap.conn

        if not sql_lib_general.is_domain_admin(domain=domain, admin=mail, conn=conn):
            raise web.seeother('/domains?msg=PERMISSION_DENIED')

        qr = sql_lib_general.export_managed_accounts(mail=mail, domains=[domain], conn=conn)
        if not qr[0]:
            raise web.seeother('/domains?msg=%s' % web.urlquote(qr[1]))

        managed_domains = qr[1]

        _domains = []
        _total_domains = 0
        _total_users = 0
        _total_lists = 0
        _total_aliases = 0

        for d in managed_domains:
            _total_domains += 1
            _domains += [d['domain']]
            _total_users += d['total_users']
            _total_lists += d['total_lists']
            _total_aliases += d['total_aliases']

        # Generate zip file
        f = io.BytesIO()
        with zipfile.ZipFile(f, mode='w', compression=zipfile.ZIP_DEFLATED) as zf:
            # Summary of all managed accounts
            content_summary = ['- Exported domains: %d' % _total_domains]
            content_summary += ['- Mailboxes: %d' % _total_users]
            content_summary += ['- Mailing lists: %d' % _total_lists]
            content_summary += ['- Mail aliases: %d' % _total_aliases]
            zf.writestr('summary.txt', '\n'.join(content_summary))

            _content_domains = ['# All managed domains:']
            _content_domains += ['# Format: domain name, display name']

            # Generate files for each domain
            for d in managed_domains:
                _domain = d['domain']
                _content_domains += ['{domain}, {name}'.format(**d)]

                for account_type in ['users', 'lists', 'aliases']:
                    if account_type == 'users':
                        _content = ['# Mailboxes under domain %s' % _domain]
                    elif account_type == 'lists':
                        _content = ['# Mailing lists under domain %s' % _domain]
                    else:
                        # account_type == 'aliases'
                        _content = ['# Mail aliases under domain %s' % _domain]

                    _content += ['# Format: mail address, display name']

                    for _account in d[account_type]:
                        _content += ['{mail}, {name}'.format(**_account)]

                    zf.writestr(_domain + '_' + account_type + '.txt', '\n'.join(_content))
            zf.writestr('domains.txt', '\n'.join(_content_domains))

        web.header('Content-Disposition', 'attachment; filename=accounts.zip')
        return f.getvalue()


class ExportAdminStatistics:
    @decorators.require_global_admin
    def GET(self):
        """
        Admin <email>
        domain1.com | 12 Mailboxes | 3 Mailinglists
        domain2.com | 9 Mailboxes | 1 Mailinglist
        """
        _wrap = SQLWrap()
        conn = _wrap.conn

        # Get all admins
        qr = sql_lib_admin.get_all_admins(email_only=True, conn=conn)

        if not qr[0]:
            return qr

        all_admins = qr[1]

        # Get all global admins
        qr = sql_lib_admin.get_all_global_admins(conn=conn)
        if not qr[0]:
            return qr

        global_admins = qr[1]
        non_global_admins = [i for i in all_admins if i not in global_admins]

        # dict used to store analyzed domain names to avoid duplicate ldap query:
        #   {'<domain>': {'user': 10,
        #                 'aliases': 23,
        #                 'maillists': 2}, ...}
        _analyzed_domains = {}

        # dict used to store admin and managed domains.
        #   {'<admin-email>': [<domain>, <domain>, ...], ...}
        # WARNING: it's possible that admin doesn't manage any domains.
        _admins_and_domains = {}

        # Write statistics in csv file.
        for _admin in non_global_admins:
            _qr = sql_lib_admin.get_managed_domains(admin=_admin,
                                                    domain_name_only=True,
                                                    listed_only=True,
                                                    conn=conn)

            if _qr[0]:
                _domains = _qr[1]
                _admins_and_domains[_admin] = _domains

                for _domain in _domains:
                    if _domain not in _analyzed_domains:
                        _num_users = sql_lib_general.num_users_under_domain(domain=_domain, conn=conn)
                        _num_aliases = sql_lib_general.num_aliases_under_domain(domain=_domain, conn=conn)
                        _num_ml = sql_lib_general.num_maillists_under_domain(domain=_domain, conn=conn)

                        _analyzed_domains[_domain] = {'users': _num_users,
                                                      'aliases': _num_aliases,
                                                      'maillists': _num_ml}

        _rows = []

        for _admin in global_admins:
            _rows.append([_admin, 'ALL'])

        for (_admin, _domains) in list(_admins_and_domains.items()):
            _rows.append([_admin, len(_domains)])

            _count = 1
            for _domain in _domains:
                _num_users = _analyzed_domains[_domain]['users']
                _num_aliases = _analyzed_domains[_domain]['aliases']
                _num_maillists = _analyzed_domains[_domain]['maillists']

                _rows.append([_count, _domain, _num_users, _num_aliases, _num_maillists])
                _count += 1

        try:
            f = io.StringIO()
            cw = csv.writer(f)

            # Header row
            cw.writerow(['Admin', 'Managed Domains', 'Users', 'Aliases', 'Mailing Lists'])

            # Data rows
            cw.writerows(_rows)

            v = f.getvalue()
        except Exception as e:
            raise web.seeother('/domains?msg=%s' % web.urlquote(repr(e)))

        web.header('Content-Disposition', 'attachment; filename=statistics_admins.csv')
        return v
