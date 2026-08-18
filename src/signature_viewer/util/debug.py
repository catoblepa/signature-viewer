# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Davide Truffa <davide@catoblepa.org>

"""Debug logging gate.

The ``SIGNATURE_VIEWER_DEBUG`` environment variable enables verbose diagnostics
that are useful while developing or troubleshooting signature verification.

Output is written to stderr (visible from a terminal) and to a debug log file
under ``XDG_CACHE_HOME/signature-viewer/debug.log`` (reachable in a Flatpak
sandbox, where plain stdout prints are usually swallowed).
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

_ENABLED = os.environ.get("SIGNATURE_VIEWER_DEBUG", "").lower() in {
    "1", "true", "yes", "on"
}

_DEBUG_LOG = None


def _ensure_log_file():
    global _DEBUG_LOG
    if _DEBUG_LOG is not None:
        return _DEBUG_LOG
    try:
        base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
        path = Path(base) / "signature-viewer" / "debug.log"
        path.parent.mkdir(parents=True, exist_ok=True)
        _DEBUG_LOG = open(path, "a", encoding="utf-8")
    except Exception:
        _DEBUG_LOG = False
    return _DEBUG_LOG


def debug(message: str):
    """Write a debug line if enabled."""
    if not _ENABLED:
        return
    line = f"[signature-viewer][debug] {message}"
    print(line, file=sys.stderr, flush=True)
    fh = _ensure_log_file()
    if fh:
        try:
            fh.write(line + "\n")
            fh.flush()
        except Exception:
            pass


def enabled() -> bool:
    return _ENABLED
