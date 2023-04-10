#!/usr/bin/env python
# Author: Zhang Huangbin <zhb@iredmail.org>

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
from libs import iredbase

# Initialize webpy app.
app = iredbase.app

if __name__ == "__main__":
    # Starting webpy builtin http server.
    # WARNING: this should not be used for production.
    app.run()
else:
    # Run as a WSGI application
    application = app.wsgifunc()
