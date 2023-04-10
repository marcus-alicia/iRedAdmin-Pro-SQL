import web


def hook_set_language():
    # parameter `lang` in URI. e.g. https://xxx/?lang=en_US
    _lang = web.input(lang=None, _method="GET").get("lang")

    # parameter `lang` in session.
    if not _lang:
        _lang = web.config.get("_session", {}).get("lang")

    web.ctx.lang = _lang or "en_US"


def hook_session():
    pass
