# SPDX-License-Identifier: GPL-3.0-or-later
"""Signature Viewer: verifica di firme digitali PAdES/CAdES (GTK4/Adwaita)."""

from __future__ import annotations

from pathlib import Path

# pyproject.toml is the single source of truth for the version. Read it
# directly so it works both when installed and in a dev checkout
# (PYTHONPATH=src) where package metadata is not available.
try:
    import tomllib
except ImportError:  # pragma: no cover - Python < 3.11
    tomllib = None  # type: ignore[assignment]


def _read_version() -> str:
    root = Path(__file__).resolve().parent.parent.parent
    candidates = [root / "pyproject.toml"]
    for path in candidates:
        if path.is_file() and tomllib is not None:
            try:
                with open(path, "rb") as f:
                    data = tomllib.load(f)
                return str(data["project"]["version"])
            except (KeyError, ValueError, OSError):
                continue
    return "0.0.0"


__version__ = _read_version()
