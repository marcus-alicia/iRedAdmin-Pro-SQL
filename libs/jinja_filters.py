"""Custom Jinja2 filters."""


def file_size_format(value, base_mb=False):
    """Convert file size to a human-readable format, e.g. 20 MB, 1 GB, 2 TB.

    @value -- file size in KB
    @base_mb -- if True, @value is in MB.
    """
    ret = "0"

    try:
        _bytes = float(value)
    except:
        return ret

    if base_mb:
        _bytes = _bytes * 1024 * 1024

    # byte
    base = 1024

    if _bytes == 0:
        return ret

    if _bytes < base:
        ret = "%d Bytes" % _bytes
    elif _bytes < base * base:
        ret = "%d KB" % (_bytes / base)
    elif _bytes < base * base * base:
        ret = "%d MB" % (_bytes / (base * base))
    elif _bytes < base * base * base * base:
        if _bytes % (base * base * base) == 0:
            ret = "%d GB" % (_bytes / (base * base * base))
        else:
            ret = "%.2f GB" % (_bytes / (base * base * base))
    else:
        if _bytes % (base * base * base * base) == 0:
            ret = "%d TB" % (_bytes / (base * base * base * base))
        else:
            ret = "%d GB" % (_bytes / (base * base * base))

    return ret


def cut_string(s, length=40):
    try:
        if len(s) != len(s.encode("utf-8", "replace")):
            length = length / 2

        if len(s) >= length:
            return s[:length] + "..."
        else:
            return s
    except UnicodeDecodeError:
        return str(s, encoding="utf-8", errors="replace")
    except:
        return s


# Return value of percentage.
def convert_to_percentage(current, total):
    try:
        current = int(current)
        total = int(total)
    except:
        return 0

    if current == 0 or total == 0:
        return 0
    else:
        percent = (current * 100) // total
        if percent < 0:
            return 0
        elif percent > 100:
            return 100
        else:
            return percent
