# Author: Zhang Huangbin <zhb@iredmail.org>
import web


def get_wblist_rdns():
    """Get wblist of rDNS."""
    whitelists = []
    blacklists = []

    try:
        qr = web.conn_iredapd.select(
            'wblist_rdns',
            what='rdns,wb',
            order='rdns',
        )

        for i in qr:
            _rdns = str(i.rdns).lower()
            if i.wb == 'W':
                whitelists.append(_rdns)
            elif i.wb == 'B':
                blacklists.append(_rdns)

        return True, {'whitelists': whitelists, 'blacklists': blacklists}
    except Exception as e:
        return False, repr(e)


def reset_wblist_rdns(whitelists=None, blacklists=None):
    """Reset wblist rdns.

    @whitelists -- a list/tuple/set of whitelist rdns domain names. Notes:
                   - if it's None, no reset.
                   - if it's empty list/tuple/set, all existing records will be
                     removed.
    @blacklists -- a list/tuple/set of blacklist rdns domain names.
    @conn -- sql connection cursor
    """
    if whitelists and blacklists:
        # Remove duplicate records
        blacklists = [i for i in blacklists if i not in whitelists]

    # Delete first to avoid possible duplicate records while inserting new
    # records later.
    for (_lists, _wb) in [(whitelists, 'W'), (blacklists, 'B')]:
        if _lists is not None:
            try:
                # Delete all existing records first
                web.conn_iredapd.delete(
                    'wblist_rdns',
                    vars={'wb': _wb},
                    where='WB=$wb',
                )
            except Exception as e:
                return False, repr(e)

    # Insert new records
    for (_lists, _wb) in [(whitelists, 'W'), (blacklists, 'B')]:
        if _lists:
            for i in _lists:
                try:
                    web.conn_iredapd.insert('wblist_rdns', rdns=i, wb=_wb)
                except:
                    pass

    return True, 'UPDATED'
