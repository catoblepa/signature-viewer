# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Davide Truffa <davide@catoblepa.org>

"""Extraction and display of information from CAdES/PAdES signatures.

Migrated from ``signature_parser.py`` of p7mviewer: ASN.1/CMS parsing with
asn1crypto and PDF signature extraction with pypdf. The actual cryptographic
verification lives in ``signature_viewer.core.verify`` (pyhanko).
"""
from __future__ import annotations

import base64
import io
from datetime import datetime

from asn1crypto import cms

from signature_viewer.util.i18n import _


def rileva_formato_p7m(data):
    """Detect if the envelope is Base64, DER or PEM.

    Returns ``('base64', decoded_data)``, ``('der', data)`` or ``('pem', data)``.
    """
    try:
        data_clean = data.strip()
        if isinstance(data_clean, bytes):
            data_clean = data_clean.decode("ascii", errors="ignore").strip()
        decoded = base64.b64decode(data_clean)
        reencoded = base64.b64encode(decoded).decode("ascii").strip()
        if (
            reencoded.replace("\n", "").replace("\r", "")
            == data_clean.replace("\n", "").replace("\r", "")
        ):
            return "base64", decoded
    except Exception:
        pass

    if isinstance(data, bytes):
        if b"-----BEGIN" in data[:100]:
            return "pem", data
        return "der", data
    return "der", data


def estrai_certificati(signed_data):
    certs = []
    if "certificates" in signed_data and signed_data["certificates"] is not None:
        for cert in signed_data["certificates"]:
            if cert.name == "certificate":
                certs.append(cert.chosen)
    return certs


def cerca_certificato_per_serial(cert_list, serial):
    for cert in cert_list:
        if cert.serial_number == serial:
            return cert
    return None


def estrai_nome_cognome(subject):
    cn = subject.native.get("common_name", "")
    gn = subject.native.get("given_name", "")
    sn = subject.native.get("surname", "")
    if gn and sn:
        return f"{gn} {sn}"
    return cn


def estrai_codice_fiscale(subject):
    cf = subject.native.get("serial_number", "")
    if cf:
        if ":" in cf:
            cf = cf.split(":")[-1]
        return cf
    return subject.native.get("dn_qualifier", "")


def estrai_organization(subject):
    org = subject.native.get("organization_name", "")
    if not org:
        org = subject.native.get("organizational_unit_name", "")
    return org if org else _("Not present")


def mostra_info_firma(signer, cert_list):
    """Return the signer information as a dictionary."""
    info = {}
    sid = signer["sid"]
    serial = None
    if sid.name == "issuer_and_serial_number":
        serial = sid.chosen["serial_number"].native
    cert = cerca_certificato_per_serial(cert_list, serial)
    not_before = not_after = None
    if cert:
        subject = cert.subject
        validity = cert["tbs_certificate"]["validity"]
        not_before = validity["not_before"].native
        not_after = validity["not_after"].native

        info[_("Identity")] = estrai_nome_cognome(subject)
        info[_("Tax Code")] = estrai_codice_fiscale(subject)
        info[_("Organization")] = estrai_organization(subject)
        if isinstance(not_before, datetime):
            info[_("Valid from")] = not_before.strftime("%d/%m/%Y %H:%M:%S")
        if isinstance(not_after, datetime):
            info[_("Valid until")] = not_after.strftime("%d/%m/%Y %H:%M:%S")
        info[_("Certificate issued by")] = cert.issuer.human_friendly

        now = (
            datetime.now(not_after.tzinfo)
            if not_after and hasattr(not_after, "tzinfo") and not_after.tzinfo
            else datetime.now()
        )
        if isinstance(not_after, datetime) and now > not_after:
            info[_("Certificate status")] = f"⚠ {_('Expired')}"
        elif isinstance(not_before, datetime) and now < not_before:
            info[_("Certificate status")] = f"⚠ {_('Not yet valid')}"
        else:
            info[_("Certificate status")] = f"✓ {_('Valid')}"
    else:
        info[_("Error")] = _("Certificate not found for this signature.")

    if "signed_attrs" in signer and signer["signed_attrs"] is not None:
        for attr in signer["signed_attrs"]:
            if attr["type"].native == "signing_time":
                signing_time = attr["values"].native[0]
                if isinstance(signing_time, datetime):
                    info[_("Signature date and time")] = signing_time.strftime(
                        "%d/%m/%Y %H:%M:%S"
                    )
                    if (
                        cert
                        and isinstance(signing_time, datetime)
                        and isinstance(not_before, datetime)
                        and isinstance(not_after, datetime)
                    ):
                        if not_before <= signing_time <= not_after:
                            info[_("Signature valid at signing time")] = f"✓ {_('Yes')}"
                        else:
                            info[_("Signature valid at signing time")] = (
                                f"✗ {_('No')} ({_('certificate not valid at signature date')})"
                            )
                break

    return info


def analizza_busta(data, livello=1):
    """Analyze a CAdES envelope (including nested) and return signer info."""
    risultati = []

    if livello == 1:
        _formato, data_convertita = rileva_formato_p7m(data)
        data = data_convertita

    try:
        content_info = cms.ContentInfo.load(data)
        if content_info["content_type"].native == "signed_data":
            signed_data = content_info["content"]
            cert_list = estrai_certificati(signed_data)
            for idx, signer in enumerate(signed_data["signer_infos"], 1):
                info_firma = mostra_info_firma(signer, cert_list)
                info_firma["tipo_firma"] = "CAdES"
                info_firma["firmatario_idx"] = idx
                info_firma["livello_busta"] = livello
                risultati.append(info_firma)
            encap_content = signed_data["encap_content_info"]["content"]
            if encap_content is not None:
                try:
                    risultati += analizza_busta(encap_content.native, livello + 1)
                except Exception:
                    pass
    except Exception:
        pass
    return risultati


def estrai_contenuto_p7m(data, livello=1):
    """Return the bytes of the original content from the envelope, or None."""
    try:
        if livello == 1:
            _formato, data_convertita = rileva_formato_p7m(data)
            data = data_convertita
        content_info = cms.ContentInfo.load(data)
        if content_info["content_type"].native == "signed_data":
            signed_data = content_info["content"]
            encap_content = signed_data["encap_content_info"]["content"]
            if encap_content is not None:
                return encap_content.native
    except Exception:
        pass
    return None


def estrai_firme_da_pdf(pdf_data):
    """Extract PAdES signatures from a PDF. Returns a list of dicts."""
    try:
        from pypdf import PdfReader
        from pypdf.generic import TextStringObject

        signatures = []
        seen_names = set()
        reader = PdfReader(io.BytesIO(pdf_data))

        for page_num, page in enumerate(reader.pages):
            annots = page.get("/Annots")
            if not annots:
                continue
            for annot_ref in annots:
                try:
                    annot = annot_ref.get_object()
                except Exception:
                    continue
                if annot.get("/FT") != "/Sig":
                    continue
                sig_value = annot.get("/V")
                if not sig_value:
                    continue
                try:
                    sig_dict = sig_value.get_object()
                    pkcs7 = sig_dict["/Contents"].get_object()
                except (KeyError, AttributeError):
                    continue

                if isinstance(pkcs7, TextStringObject):
                    pkcs7 = pkcs7.original_bytes
                if isinstance(pkcs7, str):
                    pkcs7 = bytes.fromhex(pkcs7)
                if not isinstance(pkcs7, (bytes, bytearray)) or not pkcs7:
                    continue

                name = str(annot.get("/T", "") or "")
                if name in seen_names:
                    continue
                seen_names.add(name)

                byte_range = sig_dict.get("/ByteRange")
                if byte_range:
                    byte_range = [int(x) for x in byte_range]

                rect = annot.get("/Rect")
                if rect:
                    rect = [float(x) for x in rect]

                signatures.append(
                    {
                        "pkcs7_data": bytes(pkcs7),
                        "byte_range": byte_range or [],
                        "reason": str(sig_dict.get("/Reason", "") or ""),
                        "location": str(sig_dict.get("/Location", "") or ""),
                        "name": name,
                        "page": page_num,
                        "rect": rect or [],
                    }
                )

        return signatures
    except Exception:
        return []