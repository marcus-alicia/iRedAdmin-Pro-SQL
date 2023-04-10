# Regular expressions of email address, IP address, network.

import re

# Email address.
#
#   - `+`, `=` are used in SRS rewritten addresses.
#   - `/` is sub-folder. e.g. 'john+lists/abc/def@domain.com' will create
#     directory `lists` and its sub-folders `lists/abc/`, `lists/abc/def`.
email = r"""[\w\-\#][\w\-\.\+\=\/\&\#]*@[\w\-][\w\-\.]*\.[a-zA-Z0-9\-]{2,25}"""
cmp_email = re.compile(r"^" + email + r"$", re.IGNORECASE | re.DOTALL | re.ASCII)

# Email address allowed by locally created mail user.
#
# `auth_email` allows less characters than `email`.
# Disallowed chars: `+`, `=`, `/`.
auth_email = r"""[\w\-\#][\w\-\=\.\&\#]*@[\w\-][\w\-\.]*\.[a-zA-Z0-9\-]{2,25}"""
cmp_auth_email = re.compile(r"^" + auth_email + r"$", re.IGNORECASE | re.DOTALL | re.ASCII)

# Wildcard sender address: 'user@*'
wildcard_addr = r"""[\w\-][\w\-\.\+\=]*@\*"""
cmp_wildcard_addr = re.compile(r"^" + wildcard_addr + r"$", re.IGNORECASE | re.DOTALL | re.ASCII)

#
# Domain name
#
# Single domain name.
domain = r"""[\w\-][\w\-\.]*\.[a-z0-9\-]{2,25}"""
cmp_domain = re.compile(r"^" + domain + r"$", re.IGNORECASE | re.DOTALL | re.ASCII)

# Top level domain. e.g. .com, .biz, .org.
top_level_domain = r"""[a-z0-9\-]{2,25}"""
cmp_top_level_domain = re.compile(r"^" + top_level_domain + r"$", re.IGNORECASE | re.DOTALL | re.ASCII)

# Valid first char of domain name, email address.
valid_account_first_char = r"""^[0-9a-zA-Z]{1,1}$"""
cmp_valid_account_first_char = re.compile(r"^" + valid_account_first_char + r"$", re.IGNORECASE)

# WARNING: This is used for simple URL matching, not used to verify IP address.
ip = r"[0-9a-zA-Z\.\:]+"

# Wildcard IPv4: 192.168.0.*
wildcard_ipv4 = r"(?:[\d\*]{1,3})\.(?:[\d\*]{1,3})\.(?:[\d\*]{1,3})\.(?:[\d\*]{1,3})$"
cmp_wildcard_ipv4 = re.compile(wildcard_ipv4, re.IGNORECASE | re.DOTALL)

# Mailing list id, a server-wide unique 36-char string.
mailing_list_id = r"[a-zA-Z0-9\-]{36}"
cmp_mailing_list_id = re.compile(r"^" + mailing_list_id + r"$")

# Mailing list subscription confirm token. a 32-char string.
mailing_list_confirm_token = r"[a-zA-Z0-9]{32}"
cmp_mailing_list_confirm_token = re.compile(r"^" + mailing_list_confirm_token + r"$")

#
# Mailbox
#
# Set mailbox folder name. Could be either empty or up to 20 characters.
mailbox_folder = r"""[a-zA-Z0-9]{0,20}"""
cmp_mailbox_folder = re.compile(r"^" + mailbox_folder + r"$")
