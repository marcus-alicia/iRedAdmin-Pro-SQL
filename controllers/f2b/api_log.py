from controllers import decorators
from controllers.utils import api_render

from libs.f2b import log as f2b_log


class APIBannedCount:
    @decorators.api_require_global_admin
    def GET(self):
        total = f2b_log.num_banned()
        return api_render((True, total))
