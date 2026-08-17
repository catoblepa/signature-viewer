# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Davide Truffa <davide@catoblepa.org>

import ctypes
import ctypes.util
import gettext
import locale
import os

APP_ID = "io.github.catoblepa.signature-viewer"


def _find_locale_dir():
    base = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        "/app/share/locale",
        os.path.abspath(os.path.join(base, "..", "..", "..", "..", "share", "locale")),
        os.path.abspath(os.path.join(base, "..", "..", "..", "locale")),
        os.path.abspath(os.path.join(base, "..", "..", "locale")),
    ]
    for candidate in candidates:
        if os.path.isdir(candidate):
            return candidate
    return candidates[-1]


LOCALE_DIR = _find_locale_dir()

try:
    locale.setlocale(locale.LC_ALL, "")
except Exception:
    pass

gettext.bindtextdomain(APP_ID, LOCALE_DIR)
gettext.textdomain(APP_ID)
_ = gettext.gettext


def _bind_c_textdomain():
    """Registra il dominio anche a livello C (serve a GtkBuilder/dgettext)."""
    try:
        libc = ctypes.CDLL(ctypes.util.find_library("c"))
        bind = libc.bindtextdomain
        bind.restype = ctypes.c_char_p
        bind.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        bind(APP_ID.encode(), LOCALE_DIR.encode())
        td = libc.textdomain
        td.restype = ctypes.c_char_p
        td.argtypes = [ctypes.c_char_p]
        td(APP_ID.encode())
    except Exception:
        pass


_bind_c_textdomain()