# Author: Zhang Huangbin <zhb@iredmail.org>
from libs.regxes import mailing_list_id as mlid
from libs.regxes import mailing_list_confirm_token as confirm_token

# fmt: off
urls = [
    '/newsletter/noninteractive/(subscribe)/(%s)$' % mlid, 'controllers.mlmmj.newsletter.SubUnsubSSR',
    '/newsletter/(subscribe|unsubscribe)/(%s)$' % mlid, 'controllers.mlmmj.newsletter.SubUnsub',
    '/newsletter/(subconfirm|unsubconfirm)/({})/({})$'.format(mlid, confirm_token), 'controllers.mlmmj.newsletter.SubUnsubConfirm',
    # Handle error messages
    '/newsletter/error', 'controllers.mlmmj.newsletter.Error',
]
# fmt: on
