# Author: Zhang Huangbin <zhb@iredmail.org>

import time

from dns import resolver
import requests
import web

import settings
from libs import iredutils

if settings.backend == 'ldap':
    from libs.ldaplib.admin import get_managed_domains
else:
    from libs.sqllib.admin import get_managed_domains

session = web.config.get('_session', {})


def is_pending_domain(domain, conn=None):
    if not iredutils.is_domain(domain):
        return True

    if not conn:
        conn = web.conn_iredadmin

    try:
        qr = conn.select('domain_ownership',
                         vars={'domain': domain},
                         where='(domain=$domain OR alias_domain=$domain) AND verified=0',
                         limit=1)
        if qr:
            return True
        else:
            return False
    except:
        return True


def get_pending_domains(domains=None,
                        domain_name_only=False,
                        conn=None):
    """Query `iredadmin.domain_ownership` to get list of pending domains.

    Return list of domain names."""
    admin = session.get('username')

    if domains:
        domains = [str(d).lower() for d in domains if iredutils.is_domain(d)]
    else:
        if not session.get('is_global_admin'):
            # Get managed domains
            if settings.backend == 'ldap':
                qr = get_managed_domains(admin=admin, conn=None)
            else:
                # settings.backend in ['mysql', 'pgsql']
                qr = get_managed_domains(admin=admin,
                                         domain_name_only=True,
                                         listed_only=False)

            if qr[0]:
                domains = qr[1]

                if not domains:
                    return True, []
            else:
                raise web.seeother('/domains?msg=%s' % web.urlquote(qr[1]))

    if not conn:
        conn = web.conn_iredadmin

    try:
        if session.get('is_global_admin'):
            qr = conn.select('domain_ownership',
                             where='verified=0')
        else:
            qr = conn.select('domain_ownership',
                             vars={'domains': domains, 'admin': admin},
                             where='admin=$admin AND (domain IN $domains OR alias_domain IN $domains) AND verified=0')

        if domain_name_only:
            pending_domains = set()
            for r in qr:
                if r.alias_domain:
                    pending_domains.add(r.alias_domain)
                else:
                    pending_domains.add(r.domain)

            pending_domains = [str(i).lower() for i in pending_domains if iredutils.is_domain(i)]
            pending_domains.sort()
            return True, pending_domains
        else:
            return True, list(qr)
    except Exception as e:
        return False, repr(e)


def get_verified_domains(domains=None, conn=None):
    """Query `iredadmin.domain_ownership` to get list of verified domains.

    Return list of domain names."""
    admin = session.get('username')

    if domains:
        domains = [str(d).lower() for d in domains if iredutils.is_domain(d)]
    else:
        if not session.get('is_global_admin'):
            # Get managed domains
            if settings.backend == 'ldap':
                qr = get_managed_domains(admin=admin, conn=None)
            else:
                # settings.backend in ['mysql', 'pgsql']
                qr = get_managed_domains(admin=admin,
                                         domain_name_only=True,
                                         listed_only=False)

            if qr[0]:
                domains = qr[1]
            else:
                raise web.seeother('/domains?msg=%s' % web.urlquote(qr[1]))

    if not domains:
        return True, []

    if not conn:
        conn = web.conn_iredadmin

    try:
        if session.get('is_global_admin'):
            qr = conn.select('domain_ownership',
                             what='domain,alias_domain',
                             where='verified=1')
        else:
            qr = conn.select('domain_ownership',
                             vars={'domains': domains, 'admin': admin},
                             what='domain,alias_domain',
                             where='admin=$admin AND (domain IN $domains OR alias_domain IN $domains) AND verified=1')

        verified_domains = []
        for r in qr:
            if r.alias_domain:
                verified_domains += [str(r.alias_domain).lower()]
            else:
                verified_domains += [str(r.domain).lower()]

        verified_domains.sort()
        return True, verified_domains
    except Exception as e:
        return False, repr(e)


def remove_pending_domains(domains=None):
    """Remove pending domains.

    :param domains: a list/tuple/set of domain names
    """
    if domains:
        domains = [str(d).lower() for d in domains if iredutils.is_domain(d)]
    else:
        return True,

    conn = web.conn_iredadmin

    try:
        if session.get('is_global_admin'):
            conn.delete('domain_ownership',
                        vars={'domains': domains},
                        where='(domain IN $domains OR alias_domain IN $domains) AND verified=0')
        else:
            conn.delete('domain_ownership',
                        vars={'domains': domains, 'admin': session.get('username')},
                        where='(domain IN $domains OR alias_domain IN $domains) AND admin=$admin AND verified=0')

        return True,
    except Exception as e:
        return False, repr(e)


def _generate_verify_code():
    """Generate a random and unique string as verify code."""
    s = iredutils.generate_random_strings(20)
    return settings.DOMAIN_OWNERSHIP_VERIFY_CODE_PREFIX + s


def set_verify_code_for_new_domains(primary_domain, alias_domains=None, conn=None):
    """Generate new unique verify codes for mail domains.

    primary_domain -- the primary mail domain name
    alias_domains -- alias domains of primary domain
    conn -- sql connection cursor (for `iredadmin` database)
    """
    if not settings.REQUIRE_DOMAIN_OWNERSHIP_VERIFICATION:
        # Bypass domain verification.
        return True,

    if not iredutils.is_domain(primary_domain):
        return False, 'INVALID_DOMAIN_NAME'

    if alias_domains:
        alias_domains = [str(d).lower() for d in alias_domains if iredutils.is_domain(d)]

    if not conn:
        conn = web.conn_iredadmin

    if session.get('is_global_admin'):
        admin = ''
    else:
        admin = session.get('username')

    try:
        expire = int(time.time()) + settings.DOMAIN_OWNERSHIP_EXPIRE_DAYS * 24 * 60 * 60

        if alias_domains:
            for d in alias_domains:
                try:
                    conn.insert('domain_ownership',
                                admin=admin,
                                domain=primary_domain,
                                alias_domain=d,
                                verify_code=_generate_verify_code(),
                                expire=expire)
                except Exception as e:
                    if e.__class__.__name__ != 'IntegrityError':
                        return False, repr(e)
        else:
            try:
                conn.insert('domain_ownership',
                            admin=admin,
                            domain=primary_domain,
                            verify_code=_generate_verify_code(),
                            expire=expire)
            except Exception as e:
                if e.__class__.__name__ != 'IntegrityError':
                    return False, repr(e)

        return True,
    except Exception as e:
        return False, repr(e)


def mark_ownership_as_verified(rid=None, domain=None, message=None, conn=None):
    """Update `iredadmin.domain_ownership` with `verified=1` and
    `message=<reason>` (optional).

    @rid -- the value of column `domain_ownership.id`
    @domain -- domain name of `domain_ownership.domain` or `domain_ownership.alias_domain`
    @message -- the verify message
    @conn -- sql connection cursor
    """
    if not (rid or domain):
        return True,

    if domain:
        if not iredutils.is_domain:
            return False, 'INVALID_DOMAIN_NAME'

    if not conn:
        conn = web.conn_iredadmin

    if not message:
        message = ''

    # Get value of sql column `domain_ownership.id`
    if domain:
        try:
            qr = conn.select('domain_ownership',
                             vars={'domain': domain},
                             what='id',
                             where="(alias_domain=$domain) OR (domain=$domain AND alias_domain='')",
                             limit=1)
            if qr:
                rid = qr[0].id
            else:
                return True,
        except Exception as e:
            return False, repr(e)

    try:
        conn.update('domain_ownership',
                    vars={'id': rid},
                    verified=1,
                    message=message,
                    last_verify=web.sqlliteral('NOW()'),
                    where='id=$id')
        return True,
    except Exception as e:
        return False, repr(e)


def verify_domain_ownership(domains, conn=None):
    """Verify domain ownership for given domain names.

    Returned values:

    (True, [(primary_domain, alias_domain), ...]): if some domains were
                                                   successfully verified.
    (False, <reason>): if some error happened while verifying.

    Parameters:

    @domains -- a list/tuple/set of domain names
    @conn -- sql connection cursor (of 'iredadmin' database)
    """
    domains = [str(d).lower() for d in domains if iredutils.is_domain(d)]
    if not domains:
        return True, []

    if not conn:
        conn = web.conn_iredadmin

    # Get verify code of given domains.
    if session.get('is_global_admin'):
        qr = conn.select(
            'domain_ownership',
            vars={'domains': domains},
            where="verified=0 AND ((domain IN $domains AND alias_domain='') OR (alias_domain IN $domains))",
        )
    else:
        qr = conn.select(
            'domain_ownership',
            vars={'domains': domains, 'admin': session.get('username')},
            where="verified=0 AND admin=$admin AND ((domain IN $domains AND alias_domain='') OR (alias_domain IN $domains))",
        )

    if not qr:
        return True, []

    verified_domains = []
    expire = int(time.time()) + settings.DOMAIN_OWNERSHIP_EXPIRE_DAYS * 24 * 60 * 60
    for r in qr:
        rid = int(r.id)
        domain = str(r.domain).lower()
        alias_domain = str(r.alias_domain).lower()
        verify_code = str(r.verify_code)

        if iredutils.is_domain(alias_domain):
            verify_domain = alias_domain
        else:
            verify_domain = domain

        # web files
        _web_file = str(verify_domain + '/' + verify_code)

        _verified = False
        _verified_reason = ''
        _verify_result = ''

        # Verify web files
        for _scheme in ['http', 'https']:
            url = _scheme + '://' + _web_file

            # settings.HTTP_PROXY
            _proxies = {}
            if settings.HTTP_PROXY:
                _proxies = {
                    'http': settings.HTTP_PROXY,
                    'https': settings.HTTP_PROXY,
                }

            # MAXFILESIZE, 1024)            # maximum file size allowed to download, read, fetch
            # setopt(c.BUFFERSIZE, 1024)    # buffer read size: 1024 bytes
            # _resp_code == 200:
            try:
                with requests.get(url,
                                  proxies=_proxies,
                                  verify=False,   # no SSL certificate verifying
                                  timeout=settings.DOMAIN_OWNERSHIP_VERIFY_TIMEOUT,
                                  stream=True,    # defer downloading the response body
                                  ) as resp:
                    if resp.status_code == 200:
                        pass
                    elif resp.status_code == 404:
                        _verify_result += '%s:// file not found. ' % _scheme
                    else:
                        _verify_result += '%s://, response code must be 200, but got %d. ' % (_scheme, resp.status_code)
                        continue

                    try:
                        if int(r.headers['content-length']) < 1024:
                            _body = r.content.strip()

                            if _body == verify_code:
                                _verified = True
                                _verified_reason = '%s matches' % _scheme
                                break
                        else:
                            _verify_result += '{}:// file content too long. '.format(_scheme)
                            continue
                    except Exception as e:
                        _verify_result += '{}:// error while reading file content: {}. '.format(_scheme, repr(e))
                        continue
            except Exception as e:
                _verify_result += 'Error while verifying {}://: {}. '.format(_scheme, repr(e))

        # Verify TXT type DNS record
        if not _verified:
            try:
                _res = resolver.Resolver()
                _res.timeout = settings.DOMAIN_OWNERSHIP_VERIFY_TIMEOUT
                qr_dns = _res.query(domain, 'TXT')
                for i in qr_dns:
                    _txt = i.to_text().strip('"')
                    if verify_code == _txt:
                        _verified = True
                        _verified_reason = 'DNS record matches'
                        break

                _verify_result += "Verify code is not found as one of TXT type DNS records."
            except Exception as e:
                _verify_result += 'Error while querying DNS: %s.' % repr(e)

        if _verified:
            verified_domains += [(domain, alias_domain)]

            qr = mark_ownership_as_verified(rid=rid, message=_verified_reason, conn=conn)
            if not qr[0]:
                return qr
        else:
            # Update last verify time, verify result, and expire time
            try:
                conn.update('domain_ownership',
                            message=_verify_result,
                            last_verify=web.sqlliteral('NOW()'),
                            expire=expire,
                            where='id=%d' % rid)
            except Exception as e:
                return False, repr(e)

    return True, verified_domains
