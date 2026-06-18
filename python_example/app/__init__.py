import os

_src_app = os.path.join(os.path.dirname(os.path.dirname(__file__)), "src", "app")
if _src_app not in __path__:
    __path__.append(_src_app)
