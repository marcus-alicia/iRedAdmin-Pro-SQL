# Author: Zhang Huangbin <zhb@iredmail.org>

import email
from email.header import decode_header
from libs.logger import log_traceback
from libs import iredutils


def parse_raw_message(msg: bytes):
    """Read RAW message from string. Return a tuple with 3 elements:

    - `headers`: a list of tuple with mail header. [(hdr, value), (hdr, value), ...]
    - `bodies`: a list of body parts: [part1, part2, ...]
    - `attachments`: a list of attachment file names: [name1, name2, ...]
    """

    # Get all mail headers. Sample:
    # [('From', 'sender@xx.com'), ('To', 'recipient@xx.net')]
    headers = []

    # Get decoded content parts of mail body.
    bodies = []

    # Get list of attachment names.
    attachments = []

    msg = email.message_from_bytes(msg)

    # Extract all headers.
    for (header, value) in msg.items():
        for (text, encoding) in decode_header(value):
            if encoding:
                if isinstance(text, bytes):
                    try:
                        value = iredutils.bytes2str(text)
                    except:
                        pass

            headers.append((header, value))

    for part in msg.walk():
        _content_type = part.get_content_maintype()

        # multipart/* is just a container
        if _content_type == 'multipart':
            continue

        # either a string or None.
        _filename = part.get_filename()
        if _filename:
            attachments += [_filename]

        if _content_type == 'text':
            # Plain text, not an attachment.
            try:
                if part.get_content_charset():
                    encoding = part.get_content_charset()
                elif part.get_charset():
                    encoding = part.get_charset()
                else:
                    encoding = 'utf-8'

                text = str(part.get_payload(decode=True),
                           encoding=encoding,
                           errors='replace')

                text = text.strip()
                bodies.append(text)
            except:
                log_traceback()

    return headers, bodies, attachments
