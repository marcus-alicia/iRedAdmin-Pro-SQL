import web

from controllers import decorators
from libs.logger import logger


@decorators.require_global_admin
def num_banned() -> int:
    total = 0

    try:
        _qr = web.conn_f2b.select("banned", what="COUNT(id) AS total")
        total = _qr[0]['total']
    except Exception as e:
        logger.error(e)

    return total
