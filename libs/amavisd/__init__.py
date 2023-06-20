# Author: Zhang Huangbin <zhb@iredmail.org>

from libs import iredutils

# mail_id and secret_id are composed of below characters:
#   - Amavisd-new-2.7+: [ A-Z, a-z, 0-9, -, _ ]
#   - Amavisd-new-2.6.x: [ A-Z, a-z, 0-9, +, - ]
MAIL_ID_CHARACTERS = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+-_'

WBLIST_FORM_INPUT_NAMES = {
    'wl_sender': 'whitelistSender',
    'bl_sender': 'blacklistSender',
    'wl_rcpt': 'whitelistRecipient',
    'bl_rcpt': 'blacklistRecipient',
}

# Available quarantined types in iRedAdmin web interface, and the short code
# in `amavisd.msgs` sql table.
QUARANTINE_TYPES = {
    'spam': 'S',
    'virus': 'V',
    'banned': 'B',
    'clean': 'C',
    'badheader': 'H',
    'badmime': 'M',
}

# Value of `msgs.content` and comment.
CONTENT_TYPES = {
    'B': 'Banned',
    'C': 'Clean',
    'H': 'Bad header',
    'M': 'Bad mime',
    'O': 'Oversized',
    'S': 'Spam',
    'T': 'MTA error',
    'V': 'Virus',
    'U': 'Unchecked',
}


def get_wblist_from_form(form, form_input_name):
    # Available form_input_name are listed in WBLIST_FORM_INPUT_NAMES
    input_name = WBLIST_FORM_INPUT_NAMES[form_input_name]

    addresses = []
    for _line in form.get(input_name, '').splitlines():
        if _line:
            try:
                _line = str(_line)
                addresses.append(_line)
            except:
                pass

    valid_addresses = []
    for addr in addresses:
        if iredutils.is_valid_wblist_address(addr) and (addr not in valid_addresses):
            valid_addresses.append(addr)
        else:
            continue

    return valid_addresses
