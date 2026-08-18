# SPDX-License-Identifier: GPL-3.0-or-later
"""Signature Viewer: verifica di firme digitali PAdES/CAdES (GTK4/Adwaita)."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from importlib import metadata
from pathlib import Path

# pyproject.toml is the single source of truth for the version. Because the
# Flatpak build does not install pyproject.toml (only the source tree and
# main.py), fall back to the AppStream metainfo file, which is always present
# both in a dev checkout and in the installed prefix (/app/share/metainfo).
try:
    import tomllib
except ImportError:  # pragma: no cover - Python < 3.11
    tomllib = None  # type: ignore[assignment]

_METAINFO_NAME = "io.github.catoblepa.signature-viewer.metainfo.xml"

_METAINFO_CANDIDATES = (
    # Flatpak install
    Path("/app/share/metainfo") / _METAINFO_NAME,
    # generic prefix installs
    Path("/usr/local/share/metainfo") / _METAINFO_NAME,
    Path("/usr/share/metainfo") / _METAINFO_NAME,
    # dev checkout
    Path(__file__).resolve().parent.parent.parent
    / "data" / _METAINFO_NAME,
)


def _read_version_from_metainfo() -> str | None:
    for path in _METAINFO_CANDIDATES:
        if not path.is_file():
            continue
        try:
            root = ET.parse(path).getroot()
            release = root.find(".//releases/release")
            if release is not None:
                version = release.get("version")
                if version:
                    return version
        except ET.ParseError:
            continue
    return None


def _read_version_from_pyproject() -> str | None:
    if tomllib is None:
        return None
    root = Path(__file__).resolve().parent.parent.parent
    path = root / "pyproject.toml"
    if not path.is_file():
        return None
    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
        version = data.get("project", {}).get("version")
        return str(version) if version else None
    except (ValueError, OSError):
        return None


def _read_version() -> str:
    # 1. Installed package metadata (when pip-installed).
    try:
        return metadata.version("signature-viewer")
    except metadata.PackageNotFoundError:
        pass

    # 2. AppStream metainfo (present in both Flatpak and dev checkout).
    metainfo_version = _read_version_from_metainfo()
    if metainfo_version:
        return metainfo_version

    # 3. pyproject.toml (source of truth in a dev checkout).
    pyproject_version = _read_version_from_pyproject()
    if pyproject_version:
        return pyproject_version

    return "0.0.0"


__version__ = _read_version()
