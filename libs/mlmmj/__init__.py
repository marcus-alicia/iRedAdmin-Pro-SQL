# Author: Zhang Huangbin <zhb@iredmail.org>

# Functions used to interactive with mlmmjadmin RESTful API server:
# https://bitbucket.org/iredmail/mlmmjadmin/src

import uuid
import requests
from libs import iredutils
from urllib.parse import urlencode
import settings

api_headers = {settings.MLMMJADMIN_API_AUTH_HEADER: settings.mlmmjadmin_api_auth_token}
base_url = settings.MLMMJADMIN_API_BASE_URL
_verify_ssl = settings.MLMMJADMIN_API_VERIFY_SSL


def __get(mail, params=None):
    """
    Send a http GET to mlmmjadmin RESTful API server.

    :param mail: mail address of mailing list account.
    """
    url = base_url + "/" + mail
    try:
        r = requests.get(url, headers=api_headers, params=params, verify=_verify_ssl)

        return r.json()
    except requests.ConnectionError:
        return {"_success": False, "_msg": "API_SERVER_NOT_REACHABLE"}
    except Exception as e:
        return {"_success": False, "_msg": repr(e)}


def __post(mail, data=None):
    """
    Send a http POST to mlmmjadmin RESTful API server.

    :param mail: mail address of mailing list account.
    :param data: a dict used to be sent to mlmmjadmin API server.
    """
    url = base_url + "/" + mail
    try:
        r = requests.post(url, data=data, headers=api_headers, verify=_verify_ssl)

        return r.json()
    except requests.ConnectionError:
        return {"_success": False, "_msg": "API_SERVER_NOT_REACHABLE"}
    except Exception as e:
        return {"_success": False, "_msg": repr(e)}


def __put(mail, data=None):
    """
    Send a http PUT to mlmmjadmin RESTful API server.

    :param mail: mail address of mailing list account.
    :param data: a dict used to be sent to mlmmjadmin API server.
    """
    url = base_url + "/" + mail
    try:
        r = requests.put(url, data=data, headers=api_headers, verify=_verify_ssl)

        return r.json()
    except requests.ConnectionError:
        return {"_success": False, "_msg": "API_SERVER_NOT_REACHABLE"}
    except Exception as e:
        return {"_success": False, "_msg": repr(e)}


def __delete(mail, data=None):
    """
    Send a http DELETE to mlmmjadmin RESTful API server.

    :param mail: mail address of mailing list account.
    :param data: a dict used to be encoded as URL parameters and sent to
                 mlmmjadmin API server.
    """
    url = base_url + "/" + mail

    if data:
        url = url + "?" + urlencode(data)

    try:
        r = requests.delete(url, headers=api_headers, verify=_verify_ssl)

        return r.json()
    except requests.ConnectionError:
        return {"_success": False, "_msg": "API_SERVER_NOT_REACHABLE"}
    except Exception as e:
        return {"_success": False, "_msg": repr(e)}


def __get_subscribers(mail, email_only=False):
    url = base_url + "/%s/subscribers" % mail

    params = {}
    if email_only:
        params["email_only"] = "yes"

    try:
        r = requests.get(url, params=params, headers=api_headers, verify=_verify_ssl)

        return r.json()
    except requests.ConnectionError:
        return {"_success": False, "_msg": "API_SERVER_NOT_REACHABLE"}
    except Exception as e:
        return {"_success": False, "_msg": repr(e)}


def generate_transport(mail):
    (listname, domain) = str(mail).lower().split("@", 1)
    transport = "{}:{}/{}".format(settings.MLMMJ_MTA_TRANSPORT_NAME, domain, listname)
    return transport


def generate_mlid():
    """Generate an server-wide unique uuid as mailing list id."""
    return str(uuid.uuid4())


def create_account(mail, form):
    """
    Create a mlmmj account by sending a HTTP POST to mlmmjadmin RESTful API.

    Arguments:

    :param mail: full email address of mailing list account
    :param form: form submitted by a web page
    """
    mail = str(mail).lower()
    if not iredutils.is_email(mail):
        return False, "INVALID_EMAIL"

    qr = __post(mail=mail, data=form)
    if qr["_success"]:
        return True,
    else:
        return False, qr.get("_msg", "UNKNOWN_ERROR")


def get_account_profile(mail, with_subscribers=False):
    """
    Send a HTTP GET to get mailing list profile.

    Arguments:

    @mail - full email address of mailing list account
    """
    mail = str(mail).lower()
    if not iredutils.is_email(mail):
        return False, "INVALID_EMAIL"

    qr = __get(mail=mail)
    if qr["_success"]:
        profile = qr["_data"]

        if with_subscribers:
            _qr = __get_subscribers(mail=mail, email_only=True)
            if _qr["_success"]:
                profile["subscribers"] = _qr["_data"]

        return True, profile
    else:
        return False, qr.get("_msg", "UNKNOWN_ERROR")


def update_account_profile(mail, data):
    """
    Send a HTTP PUT to mlmmjadmin RESTful API.

    Arguments:

    @mail - full email address of mailing list account
    @data - a dict of parameter/value pairs.
    """
    mail = str(mail).lower()
    if not iredutils.is_email(mail):
        return False, "INVALID_EMAIL"

    qr = __put(mail=mail, data=data)
    if qr["_success"]:
        return True,
    else:
        return False, qr.get("_msg", "UNKNOWN_ERROR")


def delete_account(mail, keep_archive=True):
    """
    Send a HTTP DELETE to mlmmjadmin RESTful API.

    Arguments:

    @mail - full email address of mailing list account
    @keep_archive - archive the account or not
    """
    mail = str(mail).lower()
    if not iredutils.is_email(mail):
        return False, "INVALID_EMAIL"

    params = {"archive": "yes"}
    if not keep_archive:
        params["archive"] = "no"

    qr = __delete(mail=mail, data=params)
    if qr["_success"]:
        return True,
    else:
        return False, qr.get("_msg", "UNKNOWN_ERROR")


def delete_accounts(mails, keep_archive=True):
    mails = [str(i).lower() for i in mails if iredutils.is_email(i)]
    if not mails:
        return True,

    for i in mails:
        qr = delete_account(mail=i, keep_archive=keep_archive)
        if not qr[0]:
            return qr[0], i + "-" + qr[1]

    return True,


def get_subscribers(mail, email_only=False):
    mail = str(mail).lower()
    if not iredutils.is_email(mail):
        return False, "INVALID_EMAIL"

    qr = __get_subscribers(mail=mail, email_only=email_only)

    if qr["_success"]:
        subscribers = qr.get("_data", [])
        return True, subscribers
    else:
        return False, qr.get("_msg", "UNKNOWN_ERROR")


def add_subscribers(mail, subscribers, subscription="normal", require_confirm=False):
    mail = str(mail).lower()
    if not iredutils.is_email(mail):
        return False, "INVALID_EMAIL"

    if subscription not in ["normal", "digest", "nomail"]:
        subscription = "normal"

    url = base_url + "/%s/subscribers" % mail

    params = {"add_subscribers": ",".join(subscribers), "subscription": subscription}

    if require_confirm in [True, "yes"]:
        params["require_confirm"] = "yes"

    r = requests.post(url, data=params, headers=api_headers, verify=_verify_ssl)

    qr = r.json()
    if qr["_success"]:
        return True,
    else:
        return False, qr.get("_msg", "UNKNOWN_ERROR")


def remove_subscribers(mail, subscribers):
    """Remove subscribers from mailing list.

    :param mail: mail address of mailing list account
    :param subscribers: a list/tuple/set of subscribers' mail addresses
    """
    mail = str(mail).lower()
    if not iredutils.is_email(mail):
        return False, "INVALID_EMAIL"

    if subscribers:
        subscribers = [i.lower() for i in subscribers]
    else:
        subscribers = []

    url = base_url + "/%s/subscribers" % mail
    params = {"remove_subscribers": ",".join(subscribers)}
    r = requests.post(url, data=params, headers=api_headers, verify=_verify_ssl)
    qr = r.json()
    if qr["_success"]:
        return True,
    else:
        return False, qr.get("_msg", "UNKNOWN_ERROR")


def remove_all_subscribers(mail):
    """Remove all subscribers from mailing list.

    :param mail: mail address of mailing list account
    """
    mail = str(mail).lower()
    if not iredutils.is_email(mail):
        return False, "INVALID_EMAIL"

    url = base_url + "/%s/subscribers" % mail
    params = {"remove_subscribers": "ALL"}
    r = requests.post(url, data=params, headers=api_headers, verify=_verify_ssl)
    qr = r.json()
    if qr["_success"]:
        return True,
    else:
        return False, qr.get("_msg", "UNKNOWN_ERROR")


def subscribe_to_lists(subscriber, lists):
    """Subscribe one mail address to multiple lists."""
    subscriber = str(subscriber).lower()
    lists = [str(i).lower() for i in lists if iredutils.is_email(i)]
    if not lists:
        return True,

    url = base_url + "/subscriber/%s/subscribe" % subscriber
    params = {"lists": ",".join(lists), "require_confirm": "no"}
    r = requests.post(url, data=params, headers=api_headers, verify=_verify_ssl)
    qr = r.json()
    if qr["_success"]:
        return True,
    else:
        return False, qr.get("_msg", "UNKNOWN_ERROR")


def get_subscribed_lists(mail, query_all_lists=False, email_only=False):
    mail = str(mail).lower()

    url = base_url + "/subscriber/%s/subscribed" % mail

    params = {"query_all_lists": "no", "email_only": "no"}
    if query_all_lists:
        params["query_all_lists"] = "yes"

    if email_only:
        params["email_only"] = "yes"

    r = requests.get(url, params=params, headers=api_headers, verify=_verify_ssl)
    qr = r.json()
    if qr["_success"]:
        return True, qr["_data"]
    else:
        return False, qr.get("_msg", "UNKNOWN_ERROR")


def remove_subscriber_from_all_subscribed_lists(subscriber):
    """Remove one subscriber from all subscribed lists under same domain."""
    if not iredutils.is_email(subscriber):
        return False, "INVALID_EMAIL"

    qr = get_subscribed_lists(mail=subscriber, email_only=True)
    if not qr[0]:
        return qr

    _lists = qr[1]

    _errors = []
    for ml in _lists:
        _qr = remove_subscribers(mail=ml, subscribers=[subscriber])
        if not _qr[0]:
            _errors += ["{}: {}".format(subscriber, repr(_qr[1]))]

    if _errors:
        return False, " ".join(_errors)
    else:
        return True,
