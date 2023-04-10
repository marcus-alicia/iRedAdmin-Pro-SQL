# Author: Zhang Huangbin <zhb@iredmail.org>

import crypt
import hashlib
import random
import string
import subprocess
from base64 import b64encode, b64decode
from hmac import compare_digest
from os import urandom
from typing import Union, List

import settings

from libs import iredutils


def __has_non_ascii_character(s):
    """
    Detect whether a string contains non-ascii character or not.
    integer ordinal of a one-character string between 32 and 126 are digits,
    letters, punctuation.
    Reference: http://docs.python.org/2/library/string.html#string.printable
    """
    for i in s:
        try:
            if not (32 <= ord(i) <= 126):
                return True
        except TypeError:
            # ord() will raise TypeError for non-ascii character
            return True

    return False


def verify_new_password(
    newpw, confirmpw, min_passwd_length=None, max_passwd_length=None, db_settings=None
):
    # Confirm password
    if newpw == confirmpw:
        passwd = newpw
    else:
        return False, "PW_MISMATCH"

    # Empty password is not allowed.
    if not passwd:
        return False, "PW_EMPTY"

    errors = []
    # Non-ascii character is not allowed
    if __has_non_ascii_character(passwd):
        errors.append("PW_NON_ASCII")

    # Get settings from db
    if not db_settings:
        params = [
            "min_passwd_length",
            "max_passwd_length",
            "password_has_letter",
            "password_has_uppercase",
            "password_has_number",
            "password_has_special_char",
        ]

        db_settings = iredutils.get_settings_from_db(params=params)

    # Get and verify password length
    if not min_passwd_length or not isinstance(min_passwd_length, int):
        min_passwd_length = db_settings["min_passwd_length"]

    if not max_passwd_length or not isinstance(max_passwd_length, int):
        max_passwd_length = db_settings["max_passwd_length"]

    if len(passwd) < min_passwd_length:
        errors.append("PW_SHORTER_THAN_MIN_LENGTH")

    if max_passwd_length > 0:
        if len(passwd) > max_passwd_length:
            errors.append("PW_GREATER_THAN_MAX_LENGTH")

    # Password restriction rules
    if db_settings["password_has_letter"]:
        if not (set(passwd) & set(string.ascii_letters)):
            errors.append("PW_NO_LETTER")

    if db_settings["password_has_uppercase"]:
        if not (set(passwd) & set(string.ascii_uppercase)):
            errors.append("PW_NO_UPPERCASE")

    if db_settings["password_has_number"]:
        if not (set(passwd) & set(string.digits)):
            errors.append("PW_NO_DIGIT_NUMBER")

    if db_settings["password_has_special_char"]:
        if not (set(passwd) & set(settings.PASSWORD_SPECIAL_CHARACTERS)):
            errors.append("PW_NO_SPECIAL_CHAR")

    if errors:
        return False, ",".join(errors)
    else:
        return True, passwd


def generate_random_password(length=10, db_settings=None):
    try:
        length = int(length)

        if length <= 0:
            length = 10
        elif length <= 10:
            # We should always suggest a strong password
            length = 10
    except:
        length = 10

    if not db_settings:
        params = [
            "min_passwd_length",
            "max_passwd_length",
            "password_has_letter",
            "password_has_uppercase",
            "password_has_number",
            "password_has_special_char",
        ]

        db_settings = iredutils.get_settings_from_db(account="global", params=params)

    if length < db_settings["min_passwd_length"]:
        length = db_settings["min_passwd_length"]

    numbers = "23456789"  # No 0, 1
    letters = "abcdefghjkmnpqrstuvwxyz"  # no i, l
    uppercases = "ABCDEFGHJKLMNPQRSTUVWXYZ"  # no I

    opts = []
    if db_settings["password_has_letter"]:
        opts += random.choice(letters)
        length -= 1

    if db_settings["password_has_uppercase"]:
        opts += random.choice(uppercases)
        length -= 1

    if db_settings["password_has_number"]:
        opts += random.choice(numbers)
        length -= 1

    if (
        db_settings["password_has_special_char"]
        and settings.PASSWORD_SPECIAL_CHARACTERS
    ):
        # Don't use few characters which may mess HTML render.
        while True:
            char = random.choice(settings.PASSWORD_SPECIAL_CHARACTERS)
            if char in ["'", '"', ">", "<"]:
                continue
            else:
                opts += char
                length -= 1
                break

    opts += list(iredutils.generate_random_strings(length))

    password = ""
    for _ in range(len(opts)):
        one = random.choice(opts)
        password += one
        opts.remove(one)

    return password


def generate_bcrypt_password(p) -> str:
    if isinstance(p, str):
        p = p.encode()

    try:
        import bcrypt
    except:
        return generate_ssha_password(p)

    return "{CRYPT}" + bcrypt.hashpw(p, bcrypt.gensalt()).decode()


def verify_bcrypt_password(challenge_password: str, plain_password: str) -> bool:
    try:
        import bcrypt
    except:
        return False

    crypt_suffixes = ("{CRYPT}$2a$", "{CRYPT}$2b$",
                      "{crypt}$2a$", "{crypt}$2b$")
    blf_crypt_suffixes = ("{BLF-CRYPT}", "{blf-crypt}")

    if challenge_password.startswith(crypt_suffixes):
        challenge_password = challenge_password[7:]
    elif challenge_password.startswith(blf_crypt_suffixes):
        challenge_password = challenge_password[11:]

    return bcrypt.checkpw(plain_password.encode(), challenge_password.encode())


def generate_md5_password(p: str) -> str:
    return crypt.crypt(p, salt=crypt.METHOD_MD5)


def verify_md5_password(challenge_password: Union[str, bytes],
                        plain_password: str) -> bool:
    """Verify salted MD5 password"""
    if isinstance(challenge_password, bytes):
        challenge_password = challenge_password.decode()

    if challenge_password.startswith(("{MD5}", "{md5}")):
        challenge_password = challenge_password[5:]
    elif challenge_password.startswith(("{CRYPT}", "{crypt}")):
        challenge_password = challenge_password[7:]

    if not (challenge_password.startswith("$")
            and len(challenge_password) == 34
            and challenge_password.count("$") == 3):
        return False

    return compare_digest(challenge_password,
                          crypt.crypt(plain_password, challenge_password))


def generate_plain_md5_password(p: Union[str, bytes]) -> str:
    if isinstance(p, str):
        p = p.encode()

    p = p.strip()
    return hashlib.md5(p).hexdigest()


def verify_plain_md5_password(challenge_password, plain_password):
    if challenge_password.startswith(("{PLAIN-MD5}", "{plain-md5}")):
        challenge_password = challenge_password[11:]

    if challenge_password == generate_plain_md5_password(plain_password):
        return True
    else:
        return False


def generate_ssha_password(p: Union[str, bytes]) -> str:
    if isinstance(p, str):
        p = p.encode()

    p = p.strip()
    salt = urandom(8)
    pw = hashlib.sha1(p)
    pw.update(salt)

    return "{SSHA}" + b64encode(pw.digest() + salt).decode()


def verify_ssha_password(challenge_password: Union[str, bytes],
                         plain_password: Union[str, bytes]) -> bool:
    """Verify SHA or SSHA (salted SHA) hash with or without prefix {SHA}, {SSHA}"""
    if isinstance(challenge_password, bytes):
        challenge_password = challenge_password.decode()

    if isinstance(plain_password, str):
        plain_password = plain_password.encode()

    if challenge_password.startswith(("{SSHA}", "{ssha}")):
        challenge_password = challenge_password[6:]
    elif challenge_password.startswith(("{SHA}", "{sha}")):
        challenge_password = challenge_password[5:]

    if len(challenge_password) < 20:
        # Not a valid SSHA hash
        return False

    try:
        challenge_bytes = b64decode(challenge_password)
        digest = challenge_bytes[:20]
        salt = challenge_bytes[20:]
        hr = hashlib.sha1(plain_password)
        hr.update(salt)
        return digest == hr.digest()
    except:
        return False


def generate_sha512_password(p: Union[str, bytes]) -> str:
    """Generate SHA512 password with prefix '{SHA512}'."""
    if isinstance(p, str):
        p = p.encode()

    p = p.strip()
    pw = hashlib.sha512(p)
    return "{SHA512}" + b64encode(pw.digest()).decode()


def verify_sha512_password(challenge_password: Union[str, bytes],
                           plain_password: Union[str, bytes]) -> bool:
    """Verify SHA512 password with or without prefix '{SHA512}'."""
    if isinstance(challenge_password, bytes):
        challenge_password = challenge_password.decode()

    if isinstance(plain_password, str):
        plain_password = plain_password.encode()

    if challenge_password.startswith(("{SHA512}", "{sha512}")):
        challenge_password = challenge_password[8:]

    if len(challenge_password) != 88:
        return False

    try:
        challenge_bytes = b64decode(challenge_password)
        digest = challenge_bytes[:64]
        hr = hashlib.sha512(plain_password)
        return digest == hr.digest()    # bytes == bytes
    except:
        return False


def verify_sha512_crypt_password(challenge_password: Union[str, bytes],
                                 plain_password: str) -> bool:
    """Verify SHA512 password with prefix '{SHA512-CRYPT}'."""
    if not challenge_password.startswith(("{SHA512-CRYPT}", "{sha512-crypt}")):
        return False

    challenge_password = challenge_password[14:]
    return compare_digest(challenge_password,
                          crypt.crypt(plain_password, challenge_password))


def generate_ssha512_password(p: Union[str, bytes]) -> str:
    """Generate salted SHA512 password with prefix '{SSHA512}'."""
    if isinstance(p, str):
        p = p.encode()

    p = p.strip()
    salt = urandom(8)
    pw = hashlib.sha512(p)
    pw.update(salt)
    return "{SSHA512}" + b64encode(pw.digest() + salt).decode()


def verify_ssha512_password(challenge_password: Union[str, bytes],
                            plain_password: Union[str, bytes]) -> bool:
    """Verify SSHA512 password with or without prefix '{SSHA512}'."""
    if isinstance(challenge_password, bytes):
        challenge_password = challenge_password.decode()

    if isinstance(plain_password, str):
        plain_password = plain_password.encode()

    if challenge_password.startswith(("{SSHA512}", "{ssha512}")):
        challenge_password = challenge_password[9:]

    # With SSHA512, hash itself is 64 bytes (512 bits/8 bits per byte),
    # everything after that 64 bytes is the salt.
    if len(challenge_password) < 64:
        return False

    try:
        challenge_bytes = b64decode(challenge_password)
        digest = challenge_bytes[:64]
        salt = challenge_bytes[64:]
        hr = hashlib.sha512(plain_password)
        hr.update(salt)

        return digest == hr.digest()
    except:
        return False


def generate_password_with_doveadmpw(scheme: str, plain_password: str) -> str:
    """Generate password hash with `doveadm pw` command.
    Return SSHA instead if no 'doveadm' command found or other error raised."""
    # scheme: CRAM-MD5, NTLM
    scheme = scheme.upper()

    p = str(plain_password).strip()

    try:
        pp = subprocess.Popen(
            args=["doveadm", "pw", "-s", scheme, "-p", p],
            stdout=subprocess.PIPE
        )
        pw = pp.communicate()[0].decode()

        if scheme in settings.HASHES_WITHOUT_PREFIXED_PASSWORD_SCHEME:
            pw = pw.lstrip("{" + scheme + "}")

        # remove '\n'
        pw = pw.strip()

        return pw
    except:
        return generate_ssha_password(p)


def verify_password_with_doveadmpw(challenge_password: Union[str, bytes],
                                   plain_password: str) -> bool:
    """Verify password hash with `doveadm pw` command."""
    if isinstance(challenge_password, bytes):
        challenge_password = challenge_password.decode()

    try:
        cmd = [
            "doveadm",
            "pw",
            "-t",
            challenge_password.strip(),
            "-p",
            plain_password.strip(),
        ]

        _return_code = subprocess.call(cmd, stdin=None, stdout=None, stderr=None, shell=False)
        if _return_code == 0:
            return True
    except:
        pass

    return False


def generate_cram_md5_password(p):
    return generate_password_with_doveadmpw("CRAM-MD5", p)


def verify_cram_md5_password(challenge_password, plain_password):
    """Verify CRAM-MD5 hash with 'doveadm pw' command."""
    if not challenge_password.lower().strip().startswith("{cram-md5}"):
        return False

    return verify_password_with_doveadmpw(challenge_password, plain_password)


def generate_ntlm_password(p):
    return generate_password_with_doveadmpw("NTLM", p)


def verify_ntlm_password(challenge_password, plain_password):
    """Verify NTLM hash with 'doveadm pw' command."""
    if "NTLM" not in settings.HASHES_WITHOUT_PREFIXED_PASSWORD_SCHEME:
        if not challenge_password.startswith(("{NTLM}", "{ntlm}")):
            # Prefix '{NTLM}' so that doveadm can verify it.
            challenge_password = "{NTLM}" + challenge_password
    else:
        if not challenge_password.startswith(("{NTLM}", "{ntlm}")):
            return False

    return verify_password_with_doveadmpw(challenge_password, plain_password)


def generate_password_hash(p: Union[str, bytes],
                           pwscheme: str = None) -> Union[str, List[str]]:
    """Generate password for LDAP mail user and admin."""
    if isinstance(p, bytes):
        p = p.decode()

    p = p.strip()
    pwscheme = pwscheme or settings.DEFAULT_PASSWORD_SCHEME

    # Supports returning multiple passwords.
    pw_schemes = pwscheme.split("+")
    pws = []

    for scheme in pw_schemes:
        if scheme == "BCRYPT":
            pw_hash = generate_bcrypt_password(p)
        elif scheme == "SSHA512":
            pw_hash = generate_ssha512_password(p)
        elif scheme == "SHA512":
            pw_hash = generate_sha512_password(p)
        elif scheme == "SSHA":
            pw_hash = generate_ssha_password(p)
        elif scheme == "MD5":
            pw_hash = "{CRYPT}" + generate_md5_password(p)
        elif scheme == "CRAM-MD5":
            pw_hash = generate_cram_md5_password(p)
        elif scheme == "PLAIN-MD5":
            pw_hash = generate_plain_md5_password(p)
        elif scheme == "NTLM":
            pw_hash = generate_ntlm_password(p)
        elif scheme == "PLAIN":
            if "PLAIN" in settings.HASHES_WITHOUT_PREFIXED_PASSWORD_SCHEME:
                pw_hash = p
            else:
                pw_hash = "{PLAIN}" + p
        else:
            pw_hash = p

        pws.append(pw_hash)

    if len(pws) == 1:
        return pws[0]
    else:
        return pws


def verify_password_hash(challenge_password: Union[str, bytes],
                         plain_password: Union[str, bytes]) -> bool:
    if isinstance(challenge_password, bytes):
        challenge_password = challenge_password.decode()

    if isinstance(plain_password, bytes):
        plain_password = plain_password.decode()

    # Check plain password and MD5 first.
    if challenge_password in [
        plain_password,
        "{PLAIN}" + plain_password,
        "{plain}" + plain_password,
    ]:
        return True
    elif verify_md5_password(challenge_password, plain_password):
        return True

    upwd = challenge_password.upper()
    if upwd.startswith(("{SSHA}", "{SHA}")):
        return verify_ssha_password(challenge_password, plain_password)
    elif upwd.startswith("{SSHA512}"):
        return verify_ssha512_password(challenge_password, plain_password)
    elif upwd.startswith(("{CRYPT}$2A$", "{CRYPT}$2B$", "{BLF-CRYPT}$2A$", "{BLF-CRYPT}$2B$", "{BLF-CRYPT}$2Y$")):
        return verify_bcrypt_password(challenge_password, plain_password)
    elif upwd.startswith(("{CRYPT}$6$", "{CRYPT}$2B$")):
        # CRYPT-SHA-512
        return verify_password_with_doveadmpw(challenge_password, plain_password)
    elif upwd.startswith("{SHA512}"):
        return verify_sha512_password(challenge_password, plain_password)
    elif upwd.startswith("{PLAIN-MD5}"):
        return verify_plain_md5_password(challenge_password, plain_password)
    elif upwd.startswith("{SHA512-CRYPT}"):
        return verify_sha512_crypt_password(challenge_password, plain_password)
    elif upwd.startswith("{CRAM-MD5}"):
        return verify_cram_md5_password(challenge_password, plain_password)
    elif upwd.startswith("{NTLM}"):
        return verify_ntlm_password(challenge_password, plain_password)

    return False


def is_supported_password_scheme(pw_hash):
    if not (pw_hash.startswith("{") and "}" in pw_hash):
        return False

    # Extract scheme name from password hash: "{SSHA}xxxx" -> "SSHA"
    try:
        scheme = pw_hash.split("}", 1)[0].split("{", 1)[-1]
        scheme = scheme.upper()

        if scheme in [
            "PLAIN",
            "CRYPT",
            "MD5",
            "PLAIN-MD5",
            "SHA",
            "SSHA",
            "SHA512",
            "SSHA512",
            "SHA512-CRYPT",
            "BCRYPT",
            "CRAM-MD5",
            "NTLM",
        ]:
            return True
    except:
        pass

    return False
