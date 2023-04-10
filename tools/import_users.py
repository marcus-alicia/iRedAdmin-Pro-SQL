#!/usr/bin/env python3
# Purpose: Read mail accounts from given plain text file (in specified format),
#          then create them with iRedAdmin-Pro RESTful API interface.
#
# Usage:
#
#   - Make sure your iRedAdmin-Pro has RESTful API interface enabled by
#     following our tutorial:
#     https://docs.iredmail.org/iredadmin-pro.restful.api.html#enable-restful-api
#
#   - Generate file /opt/users.list which contains the mail accounts you want
#     to import, one account per line, with account info stored in few fields:
#
#     1: [REQUIRED] user's full email address.
#     2: [REQUIRED] plain text or password hash which starts with the password
#                   scheme name. For example, "{SSHA}xxx", "{SSHA512}xxx".
#     3: [optional] mailbox quota in MB. Must be an integer number.
#     4: [optional] full display name.
#     5: [optional] list of mailing list addresses. If not empty, user will be
#                   assigned to given mailing lists as a member.
#
#                   Notes:
#
#                   - Multiple addresses must be separated by ":".
#                   - If mailing list doesn't exist, it will not be created automatically.
#     6: [optional] employeeid: employee id.
#
#     NOTE: the separator "," for ending EMPTY optional fields is not required.
#
#     Samples:
#
#       user@domain.com, plain_password
#       user@domain.com, plain_password, 1024, Zhang Huangbin, list1@domain.com:list2@domain.com
#       user@domain.com, plain_password, , , list1@domain.com:list2@domain.com
#       user@domain.com, plain_password, 1024, Zhang Huangbin
#
#   - Update 3 parameters in this file:
#
#       api_endpoint = ''
#       verify_cert = True
#       admin = 'postmaster@a.io'
#       pw = 'password'
#
#     - "api_endpoint" is the endpoint of iRedAdmin-Pro RESTful API.
#     - With "verify_cert = True", a valid ssl cert is required on API
#       server (https://). If you don't have a valid ssl cert yet, please set
#       it to False.
#     - "admin" is the email address of domain admin which has privilege to
#             manage the email domain which you're going to import users to.
#     - "pw" is plain password of domain admin.
#
#   - Run commands below to create users listed in the "/opt/users.list" file:
#
#       python import_users.py /opt/users.list

import os
import sys
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Endpoint of iRedAdmin-Pro RESTful API
api_endpoint = 'http://127.0.0.1:8080/api'

# Verify SSL cert of API server.
# If you don't have a valid SSL cert yet, please set it to False.
verify_cert = True

# Domain admin email address and password
admin = 'postmaster@a.io'
pw = 'www'

# Define the order of fields in each line. Fields must be separated by comma.
#
#
# WARNING: For empty optional fields, a comma is still required as placeholder.
#
# Samples:
#
#   user@domain.com, plain_password, , ,
#   user@domain.com, plain_password, 1024, Zhang Huangbin, list1@domain.com:list2@domain.com,
#   user@domain.com, plain_password, , , list1@domain.com:list2@domain.com,
#   user@domain.com, plain_password, 1024, Zhang Huangbin,,
#
field_map = ['mail', 'password', 'quota', 'name', 'groups', 'employeeid']

rootdir = os.path.abspath(os.path.dirname(__file__)) + '/../'
sys.path.insert(0, rootdir)
from libs import iredutils


def __get(url, data=None):
    _url = api_endpoint + url
    r = requests.get(_url, data=data, cookies=cookies, verify=verify_cert)
    return r.json()


def __post(url, data=None):
    _url = api_endpoint + url
    r = requests.post(_url, data=data, cookies=cookies, verify=verify_cert)
    return r.json()


def __put(url, data=None):
    _url = api_endpoint + url
    r = requests.put(_url, data=data, cookies=cookies, verify=verify_cert)
    return r.json()


def __delete(url, data=None):
    _url = api_endpoint + url
    r = requests.delete(_url, data=data, cookies=cookies, verify=verify_cert)
    return r.json()


def usage():
    pass


if len(sys.argv) != 2 or len(sys.argv) > 2:
    print("Usage: $ python bulk_import.py /path/to/file")
    usage()
    sys.exit()
else:
    file = sys.argv[1]
    if not os.path.exists(file):
        print("<<< ERROR >>> file does not exist: {}".format(file))
        sys.exit()

#
# Login
#
r = requests.post(api_endpoint + '/login',
                  data={'username': admin, 'password': pw},
                  verify=verify_cert)

# Get returned JSON data
res = r.json()
if not res['_success']:
    sys.exit('Login failed')

cookies = r.cookies

# Read user list.
f = open(file, 'rb')

for line in f.readlines():
    line = iredutils.bytes2str(line.strip())
    fields = line.split(',')

    try:
        d = {}
        for (k, v) in zip(field_map, fields):
            d[k] = v
    except:
        sys.exit("<<< ERROR >>> line has invalid format:\n{}".format(line))

    # Get user mail address
    mail = d.pop('mail')
    mail.lower()
    if not iredutils.is_email(mail):
        sys.exit("<<< ERROR >>> line has invalid user email address: {}\nLine: {}".format(mail, line))

    password = d.pop('password')
    name = d.pop("name", mail.split("@", 1)[0])
    quota = d.pop("quota", "0")

    # Get mail address(es) of assigned mailing list(s)
    groups = d.pop('groups', "")
    groups.lower()
    groups = [addr.lower().strip() for addr in groups.split(':') if iredutils.is_email(addr)]

    # Create user
    res = __post('/user/' + mail,
                 data={'name': name,
                       'password': password.strip(),
                       'quota': quota})

    if res['_success']:
        print("[OK] Created user: {}".format(mail))
    else:
        if res['_msg'] == 'ALREADY_EXISTS':
            print("[SKIP] Account already exists: {}.".format(mail))
            continue
        else:
            sys.exit('<<< ERROR >>> failed to create user: {}'.format(res))

    if password.startswith('{'):
        res = __put('/user/' + mail,
                    data={'password_hash': password})

        if res['_success']:
            print("  |- [OK] Updated user password (hash): {}".format(mail))
        else:
            sys.exit('<<< ERROR >>> failed to updated user password (hash): {}, error: {}'.format(mail, res))

    if groups:
        for group in groups:
            res = __put('/ml/' + group,
                        data={'add_subscribers': mail,
                              'require_confirm': 'no'})

            if res['_success']:
                print("  |- [OK] Subscribed user to mailing list: {} -> {}".format(mail, group))
            else:
                print('<<< WARNING >>> failed to subscribe user to mailing list: {} -> {}, error: {}'.format(mail, group, res))

    employeeid = d.pop("employeeid", "")
    if employeeid:
        res = __put('/user/' + mail,
                    data={'employeeid': employeeid})

        if res['_success']:
            print("  |- [OK] Updated employeeid: {}".format(mail))
        else:
            sys.exit('<<< ERROR >>> failed to updated employeeid: {}, error: {}'.format(mail, res))
