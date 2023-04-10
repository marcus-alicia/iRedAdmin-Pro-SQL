#!/usr/bin/env python3

# Author:   Zhang Huangbin <zhb@iredmail.org>
# Updated:  2012.07.01
# Purpose:  Dump disclaimer text from OpenLDAP directory server or SQL servers.
# Requirements: iRedMail-0.5.0 or later releases
#
# Shipped within iRedAdmin-Pro: http://www.iredmail.org/admin_panel.html

# USAGE:
#
#   - Make sure you have correct backend related settings in iRedAdmin config
#     file, settings.ini.
#
#   - Test this script in command line directly, make sure no errors in output
#     message.
#
#       # python /path/to/dump_disclaimer.py /etc/postfix/disclaimer/
#
#   - Setup a cron job to execute this script daily. For example: execute
#     this script at 2:01AM every day.
#
#       1  2   *   *   *   python /path/to/dump_disclaimer.py /etc/postfix/disclaimer/
#
# That's all.

import os
import sys
import web

web.config.debug = False

# Directory used to store disclaimer files.
# Default directory is /etc/postfix/disclaimer/.
# Default disclaimer file name is [domain_name].txt
if len(sys.argv) != 2:
    sys.exit('Error: Please specify a directory used to store disclaimer, default is /etc/postfix/disclaimer/')
else:
    DISCLAIMER_DIR = sys.argv[1]
    DISCLAIMER_FILE_EXT = '.txt'

os.environ['LC_ALL'] = 'C'
rootdir = os.path.abspath(os.path.dirname(__file__)) + '/../'
sys.path.insert(0, rootdir)

import settings
from libs import iredutils
from tools import ira_tool_lib
logger = ira_tool_lib.logger

if settings.backend == 'ldap':
    import ldap
elif settings.backend == 'mysql':
    sql_dbn = 'mysql'
elif settings.backend == 'pgsql':
    sql_dbn = 'postgres'


def write_disclaimer(text, filename, file_type='txt'):
    # Write plain text
    try:
        f = open(filename, 'w')

        if file_type == 'html':
            html = """<div id="disclaimer_separator"><p>----------</p><br /></div>"""
            html += """<div id="disclaimer_text"><p>""" + text + """</p></div>"""

            f.write('\n' + html + '\n')
        else:
            f.write('\n---------\n' + text + '\n')
        logger.info("  + %s" % filename)
        f.close()
    except Exception as e:
        logger.info('<<< ERROR >>> %s' % str(e))


def handle_disclaimer(domain, disclaimer_text):
    """Dump or remove disclaimer text."""
    txt = os.path.join(DISCLAIMER_DIR, domain + '.txt')
    html = os.path.join(DISCLAIMER_DIR, domain + '.html')

    if disclaimer_text:
        write_disclaimer(text=disclaimer_text,
                         filename=txt,
                         file_type='txt')

        write_disclaimer(text=disclaimer_text,
                         filename=html,
                         file_type='html')
    else:
        # Remove old disclaimer file if no disclaimer setting
        try:
            for f in [txt, html]:
                if os.path.isfile(f):
                    os.remove(f)
                    logger.info("  - Remove %s." % f)
        except OSError:
            pass
        except Exception as e:
            # Other errors.
            logger.info("<<< ERROR >>> {}: {}.".format(domain, str(e)))


def dump_from_ldap():
    """Dump disclaimer text from LDAP server."""
    logger.info('Connecting to LDAP server')
    conn = ldap.initialize(uri=settings.ldap_uri,
                           trace_level=0,
                           bytes_strictness='silent')
    conn.set_option(ldap.OPT_PROTOCOL_VERSION, 3)

    logger.info('Binding with dn: %s' % settings.ldap_basedn)
    conn.bind_s(settings.ldap_bind_dn, settings.ldap_bind_password)

    # Search and get disclaimer.
    logger.info('Searching all domains')
    qr = conn.search_s(
        settings.ldap_basedn,
        ldap.SCOPE_ONELEVEL,
        '(objectClass=mailDomain)',
        ['domainName', 'domainAliasName', 'disclaimer'],
    )

    logger.info('Dumping ...')

    for (_dn, _ldif) in qr:
        _ldif = iredutils.bytes2str(_ldif)

        # Get domain names.
        _domains = _ldif['domainName']
        _alias_domains = _ldif.get('domainAliasName', [])
        disclaimer_text = _ldif.get('disclaimer', [''])[0]

        domains = _domains + _alias_domains

        for domain in domains:
            handle_disclaimer(domain, disclaimer_text)

    conn.unbind()
    logger.info('Connection closed.')


def dump_from_sql():
    """Dump disclaimer text from MySQL or PostgreSQL server."""
    logger.info("Connecting to SQL server '%s:%d' as user '%s' ..." % (settings.vmail_db_host,
                                                                       int(settings.vmail_db_port),
                                                                       settings.vmail_db_user))

    conn = web.database(dbn=sql_dbn,
                        host=settings.vmail_db_host,
                        port=int(settings.vmail_db_port),
                        db=settings.vmail_db_name,
                        user=settings.vmail_db_user,
                        pw=settings.vmail_db_password)

    logger.info('Get all alias domains')
    qr = conn.select('alias_domain', what='alias_domain, target_domain')
    alias_domains = {}
    for i in qr:
        _alias_domain = str(i.alias_domain).lower()
        _target_domain = str(i.target_domain).lower()

        if _target_domain in alias_domains:
            alias_domains[_target_domain].append(_alias_domain)
        else:
            alias_domains[_target_domain] = [_alias_domain]

    # Search and get disclaimer.
    logger.info('Get all primary domains')
    qr = conn.select('domain', what='domain, disclaimer')

    # Dump disclaimer for every domain.
    logger.info('Dumping...')
    for r in qr:
        domain = str(r.domain).lower()
        disclaimer_text = r.disclaimer

        domains = [domain] + alias_domains.get(domain, [])

        logger.info(domain)
        for domain in domains:
            handle_disclaimer(domain, disclaimer_text)

    logger.info('Completed.')


if settings.backend == 'ldap':
    dump_from_ldap()
elif settings.backend in ['mysql', 'pgsql']:
    dump_from_sql()
