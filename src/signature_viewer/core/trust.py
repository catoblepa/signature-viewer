# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Davide Truffa <davide@catoblepa.org>

"""Trust anchors: system certificates (p11-kit-trust) + European TSL.

Unlike system-only anchors (which must be installed/updated manually), the
official TSL (Trusted Service List) is downloaded at regular intervals and
cached, so that qualified certificates (e.g. InfoCamere, InfoCert, Aruba,
Actalis) stay up to date.
"""
from __future__ import annotations

import base64
import json
import logging
import os
import threading
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from asn1crypto import x509

from signature_viewer.util.i18n import _

_logger = logging.getLogger(__name__)

_tsl_lock = threading.Lock()

# Italian TSL published by AgID (official HTTPS channel).
IT_TSL_URL = "https://eidas.agid.gov.it/TL/TSL-IT.xml"

TSL_NS = "http://uri.etsi.org/02231/v2#"
SERVICE_STATUS_GRANTED = "granted"

# Qualified service types whose certificates are used as anchors.
SERVICE_TYPES = (
    "http://uri.etsi.org/TrstSvc/Svctype/CA/QC",
    "http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST",
    "http://uri.etsi.org/TrstSvc/Svctype/TSA/TSS-QC",
)

MAX_TSL_AGE_DAYS = 7

P11_MODULE_DIRS = [
    "/usr/lib/pkcs11",
    "/usr/lib64/pkcs11",
    "/lib/pkcs11",
    "/lib64/pkcs11",
    "/usr/lib/x86_64-linux-gnu/pkcs11",
]


def cache_dir() -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "signature-viewer"


# --- system trust anchors ---

def find_p11_trust_module() -> Optional[str]:
    for module_dir in P11_MODULE_DIRS:
        if not os.path.isdir(module_dir):
            continue
        for entry in os.listdir(module_dir):
            if entry == "p11-kit-trust.so":
                return os.path.join(module_dir, entry)
    return None


def load_system_trust_roots() -> List[x509.Certificate]:
    """System trust anchors from the p11-kit-trust module."""
    module_path = find_p11_trust_module()
    if module_path is None:
        return []

    roots: list[x509.Certificate] = []
    seen: set = set()
    try:
        import pkcs11
        from pkcs11 import Attribute, ObjectClass
        from pkcs11.attributes import AttributeMapper

        mapper = AttributeMapper()
        mapper.attribute_types[Attribute.VALUE] = (bytes, bytes)

        lib = pkcs11.lib(module_path)
        for slot in lib.get_slots():
            try:
                token = slot.get_token()
            except Exception:
                continue
            if not token.label:
                continue
            session = token.open(rw=False, attribute_mapper=mapper)
            for obj in session.get_objects({Attribute.CLASS: ObjectClass.CERTIFICATE}):
                value = obj.get_attributes([Attribute.VALUE]).get(Attribute.VALUE)
                if not value:
                    continue
                try:
                    cert = x509.Certificate.load(bytes(value))
                except Exception:
                    continue
                key = cert.issuer_serial
                if key in seen:
                    continue
                seen.add(key)
                roots.append(cert)
    except Exception as exc:
        _logger.warning("reading system trust anchors failed: %s", exc)

    return roots


# --- European TSL ---

def _parse_tsl(xml_bytes: bytes) -> List[x509.Certificate]:
    root = ET.fromstring(xml_bytes)
    certs: list[x509.Certificate] = []
    seen: set = set()

    for tsp in root.findall(
        f"{{{TSL_NS}}}TrustServiceProviderList/{{{TSL_NS}}}TrustServiceProvider"
    ):
        for service in tsp.findall(f"{{{TSL_NS}}}TSPServices/{{{TSL_NS}}}TSPService"):
            info = service.find(f"{{{TSL_NS}}}ServiceInformation")
            if info is None:
                continue
            service_type = info.findtext(f"{{{TSL_NS}}}ServiceTypeIdentifier") or ""
            status = info.findtext(f"{{{TSL_NS}}}ServiceStatus") or ""
            if service_type not in SERVICE_TYPES:
                continue
            if status.split("/")[-1] != SERVICE_STATUS_GRANTED:
                continue
            for digital_id in info.findall(
                f"{{{TSL_NS}}}ServiceDigitalIdentity/{{{TSL_NS}}}DigitalId"
            ):
                for element in digital_id.findall(f"{{{TSL_NS}}}X509Certificate"):
                    der = base64.b64decode("".join(element.text.split()))
                    try:
                        cert = x509.Certificate.load(der)
                    except Exception:
                        continue
                    key = cert.issuer_serial
                    if key in seen:
                        continue
                    seen.add(key)
                    certs.append(cert)
    return certs


def _tsl_cache_files() -> tuple[Path, Path]:
    directory = cache_dir() / "tsl"
    return directory / "certs.json", directory / "fetched_at"


def _read_tsl_cache() -> Optional[List[x509.Certificate]]:
    certs_path, _fetched = _tsl_cache_files()
    if not certs_path.exists():
        return None
    try:
        data = json.loads(certs_path.read_text(encoding="utf-8"))
        return [x509.Certificate.load(base64.b64decode(b)) for b in data]
    except Exception as exc:
        _logger.warning("TSL cache not readable: %s", exc)
        return None


def _write_tsl_cache(certs: List[x509.Certificate]) -> None:
    certs_path, fetched_path = _tsl_cache_files()
    try:
        certs_path.parent.mkdir(parents=True, exist_ok=True)
        data = [base64.b64encode(cert.dump()).decode("ascii") for cert in certs]
        certs_path.write_text(json.dumps(data), encoding="utf-8")
        fetched_path.write_text(
            datetime.now(timezone.utc).isoformat(), encoding="utf-8"
        )
    except Exception as exc:
        _logger.warning("saving TSL cache failed: %s", exc)


def _tsl_cache_is_fresh() -> bool:
    _, fetched_path = _tsl_cache_files()
    if not fetched_path.exists():
        return False
    try:
        fetched = datetime.fromisoformat(fetched_path.read_text().strip())
        age = datetime.now(timezone.utc) - fetched
        return age.days < MAX_TSL_AGE_DAYS
    except Exception:
        return False


def _fetch_tsl(url: str = IT_TSL_URL) -> bytes:
    import requests

    response = requests.get(url, timeout=30)
    response.raise_for_status()
    return response.content


def refresh_tsl_roots() -> Optional[List[x509.Certificate]]:
    """Download the TSL, extract the anchors and update the cache. Returns the
    downloaded anchors or None on network error."""
    with _tsl_lock:
        try:
            xml_bytes = _fetch_tsl()
            certs = _parse_tsl(xml_bytes)
            if certs:
                _write_tsl_cache(certs)
            return certs
        except Exception as exc:
            _logger.warning("TSL refresh failed: %s", exc)
            return None


def load_tsl_roots() -> List[x509.Certificate]:
    """Anchors from the TSL: use the cache if fresh, otherwise refresh."""
    cached = _read_tsl_cache()
    if cached and _tsl_cache_is_fresh():
        return cached
    fresh = refresh_tsl_roots()
    if fresh:
        return fresh
    # fallback: cache even if stale
    return cached or []


def load_tsl_roots_cached() -> List[x509.Certificate]:
    """Anchors from the TSL cache without blocking on a network refresh.

    Used on the verification path so that opening a document never waits on a
    TSL download; the background/startup refresh keeps the cache up to date.
    """
    cached = _read_tsl_cache()
    return cached or []


def load_trust_roots() -> List[x509.Certificate]:
    """Overall trust anchors: system + TSL (deduplicated)."""
    roots = load_system_trust_roots()
    seen = {cert.issuer_serial for cert in roots}
    for cert in load_tsl_roots():
        if cert.issuer_serial not in seen:
            seen.add(cert.issuer_serial)
            roots.append(cert)
    return roots


def load_trust_roots_cached() -> List[x509.Certificate]:
    """Trust anchors using only the cached TSL, without network access.

    Preferred on the verification path so opening a document never blocks on a
    TSL download; the background refresh updates the cache in the meantime.
    """
    roots = load_system_trust_roots()
    seen = {cert.issuer_serial for cert in roots}
    for cert in load_tsl_roots_cached():
        if cert.issuer_serial not in seen:
            seen.add(cert.issuer_serial)
            roots.append(cert)
    return roots