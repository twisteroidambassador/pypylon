import selectors

import libzt


class LibztSelector(selectors.SelectSelector):
    def _select(self, r, w, x, timeout=None):
        return libzt.select(r, w, x, timeout)
