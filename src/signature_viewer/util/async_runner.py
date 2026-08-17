# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Davide Truffa <davide@catoblepa.org>

"""Esegue coroutine asyncio in un thread dedicato e consegna il risultato
alla UI tramite GLib (il loop GTK non è un loop asyncio)."""
from __future__ import annotations

import asyncio
import threading
from typing import Any, Callable, Optional

import gi

gi.require_version("GLib", "2.0")
from gi.repository import GLib


def run_coroutine(
    coro_factory,
    on_done: Callable[[Any], None],
    on_error: Optional[Callable[[BaseException], None]] = None,
):
    """Esegue la coroutine prodotta da `coro_factory` in un thread dedicato;
    `on_done(result)` o `on_error(exc)` vengono invocati nel thread principale
    via GLib.idle_add. Accetta anche una coroutine già pronta."""

    def worker():
        try:
            coro = coro_factory() if callable(coro_factory) else coro_factory
            result = asyncio.run(coro)
            error = None
        except BaseException as exc:  # noqa: BLE001 - riportiamo alla UI
            result = None
            error = exc

        def deliver():
            if error is not None and on_error is not None:
                on_error(error)
            elif error is None:
                on_done(result)

        GLib.idle_add(deliver)

    threading.Thread(target=worker, daemon=True).start()