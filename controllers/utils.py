# Author: Zhang Huangbin <zhb@iredmail.org>

import simplejson as json
import web


class Redirect:
    """Make url ending with or without '/' going to the same class."""

    def GET(self, path):
        raise web.seeother("/" + str(path))


class Expired:
    def GET(self):
        web.header("Content-Type", "text/html")
        return """<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">

    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>
        <title>License expired</title>
    </head>

    <body>
        <p>Your license of iRedAdmin-Pro expired, please <a href="http://www.iredmail.org/pricing.html" target="_blank" rel='noopener'>purchase a new license</a> to continue using iRedAdmin-Pro.</p>
    </body>
</html>
"""


def _render_json(d):
    web.header("Content-Type", "application/json")
    return json.dumps(d)


def api_render(data):
    """Convert given data to a dict and render it.

    - if `data` is a dict, return it directly.
    - if `data` is a tuple:
        - (True, )      -> {'_success': True}
        - (True, xxx)   -> {'_success': True, '_data': xxx}
        - (False, )     -> {'_success': False}
        - (False, xxx)  -> {'_success': False, '_msg': xxx}
    - if `data` is a boolean value (True, False), return {'_success': <boolean>}
    """
    if isinstance(data, dict):
        d = data
    elif isinstance(data, tuple):
        if data[0] is True:
            if len(data) == 2:
                d = {"_success": True, "_data": data[1]}
            else:
                d = {"_success": True}
        else:
            if len(data) == 2:
                d = {"_success": False, "_msg": data[1]}
            else:
                d = {"_success": False}

    elif isinstance(data, bool):
        d = {"_success": data}
    else:
        d = {"_success": False, "_msg": repr(data)}

    return _render_json(d)
