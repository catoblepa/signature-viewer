# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Davide Truffa <davide@catoblepa.org>

"""Cryptographic verification and trust chain validation.

Uses pyhanko (CMS/PDF validation) and pyhanko-certvalidator for the trust
chain. Trust anchors (system + European TSL) are managed in
``signature_viewer.core.trust``.
"""
from __future__ import annotations

import io
import logging
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from asn1crypto import cms, x509
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation.generic_cms import async_validate_cms_signature
from pyhanko.sign.validation.pdf_embedded import (
    async_validate_pdf_signature,
    collect_embedded_signatures,
)
from pyhanko_certvalidator import ValidationContext
from pyhanko_certvalidator.registry import SimpleCertificateStore

from signature_viewer.core import display, trust
from signature_viewer.util.i18n import _

_logger = logging.getLogger(__name__)

# re-export for compatibility
load_system_trust_roots = trust.load_system_trust_roots
load_trust_roots = trust.load_trust_roots


@dataclass
class SignerReport:
    """Validation result for a single signer."""

    info: dict
    valid: bool
    trusted: bool
    summary: str
    page: Optional[int] = None
    box: Optional[Tuple[float, float, float, float]] = None
    field_name: str = ""


@dataclass
class VerificationReport:
    """Overall result of a document verification."""

    file_format: str
    status: str  # valid_trusted | valid_untrusted | invalid | no_signatures | error
    message: str
    signers: List[SignerReport] = field(default_factory=list)


def build_validation_context(
    trust_roots: Optional[List[x509.Certificate]] = None,
    allow_fetching: bool = True,
) -> ValidationContext:
    """Build the validation context with the trust anchors.

    If ``trust_roots`` is not given, uses the system anchors + the European
    TSL (updated at regular intervals). With ``allow_fetching=True`` (default)
    OCSP/CRL are downloaded from the URLs declared in the certificates
    (revocation check, soft-fail).
    """
    if trust_roots is None:
        trust_roots = trust.load_trust_roots()
    store = SimpleCertificateStore()
    for cert in trust_roots:
        store.register(cert)
    return ValidationContext(trust_roots=store, allow_fetching=allow_fetching)


def _report_error(file_format: str, error) -> VerificationReport:
    _logger.debug("verification failed: %s", error)
    return VerificationReport(
        file_format=file_format,
        status="error",
        message=f"{_('Verification error')}: {error}",
    )


def _report_no_signatures(file_format: str) -> VerificationReport:
    return VerificationReport(
        file_format=file_format,
        status="no_signatures",
        message=_("No digital signature found in file"),
    )


async def verify_cades(
    data: bytes, validation_context: Optional[ValidationContext] = None
) -> VerificationReport:
    """Verify a CAdES envelope (DER/PEM/Base64)."""
    if validation_context is None:
        validation_context = build_validation_context()

    _formato, data_der = display.rileva_formato_p7m(data)

    try:
        content_info = cms.ContentInfo.load(data_der)
        if content_info["content_type"].native != "signed_data":
            return _report_no_signatures("CAdES")
        signed_data = content_info["content"]
    except Exception:
        return _report_no_signatures("CAdES")

    try:
        status = await async_validate_cms_signature(
            signed_data, validation_context=validation_context
        )
    except Exception as exc:
        return _report_error("CAdES", exc)

    signer_infos = display.analizza_busta(data_der)
    summary = status.summary()
    signers = [
        SignerReport(
            info=info,
            valid=status.valid,
            trusted=status.trusted,
            summary=summary,
        )
        for info in signer_infos
    ]

    if status.valid and status.trusted:
        return VerificationReport(
            file_format="CAdES",
            status="valid_trusted",
            message=_("Verification completed successfully"),
            signers=signers,
        )
    if not status.valid:
        return VerificationReport(
            file_format="CAdES",
            status="invalid",
            message=_(
                "The signature is not valid: the document may have been modified"
            ),
            signers=signers,
        )
    return VerificationReport(
        file_format="CAdES",
        status="valid_untrusted",
        message=_("Signature valid, but the certificate chain is not trusted"),
        signers=signers,
    )


async def verify_pades(
    pdf_bytes: bytes, validation_context: Optional[ValidationContext] = None
) -> VerificationReport:
    """Verify the PAdES signatures of a PDF."""
    if validation_context is None:
        validation_context = build_validation_context()

    try:
        reader = PdfFileReader(io.BytesIO(pdf_bytes))
        embedded = list(collect_embedded_signatures(reader))
    except Exception as exc:
        return _report_error("PAdES", exc)

    if not embedded:
        return _report_no_signatures("PAdES")

    pdf_signatures = display.estrai_firme_da_pdf(pdf_bytes)
    signers: List[SignerReport] = []

    for embedded_sig in embedded:
        try:
            status = await async_validate_pdf_signature(
                embedded_sig, signer_validation_context=validation_context
            )
        except Exception as exc:
            return _report_error("PAdES", exc)

        info = {}
        if status.signing_cert is not None:
            subject = status.signing_cert.subject
            info[_("Identity")] = display.estrai_nome_cognome(subject)
            info[_("Tax Code")] = display.estrai_codice_fiscale(subject)
            info[_("Organization")] = display.estrai_organization(subject)
            info[_("Certificate issued by")] = (
                status.signing_cert.issuer.human_friendly
            )

        page = None
        box = None
        field_name = ""
        sig_field = getattr(embedded_sig, "sig_field", None)
        if sig_field is not None:
            try:
                field_name = str(sig_field.get("/T") or "")
            except Exception:
                pass

        # Match this embedded signature with the pypdf-extracted one (by
        # PKCS#7 blob first, then by field name) to get page and rectangle.
        matched = None
        try:
            raw = sig_field.get("/Contents")
            if isinstance(raw, str):
                raw = bytes.fromhex(raw)
            elif hasattr(raw, "original_bytes"):
                raw = raw.original_bytes
            if raw:
                for pdf_sig in pdf_signatures:
                    if bytes(raw) == pdf_sig["pkcs7_data"]:
                        matched = pdf_sig
                        break
        except Exception:
            pass
        if matched is None:
            for pdf_sig in pdf_signatures:
                if field_name and pdf_sig.get("name") == field_name:
                    matched = pdf_sig
                    break
        if matched is None and pdf_signatures:
            matched = pdf_signatures[0]

        if matched is not None:
            page = matched.get("page")
            box = tuple(float(x) for x in matched["rect"]) if len(matched.get("rect", [])) == 4 else None
            parsed = display.analizza_busta(matched["pkcs7_data"])
            if parsed:
                info = {**parsed[0], **info}
            if matched.get("reason"):
                info[_("Reason")] = matched["reason"]
            if matched.get("location"):
                info[_("Location")] = matched["location"]

        signers.append(
            SignerReport(
                info=info,
                valid=status.valid,
                trusted=status.trusted,
                summary=status.summary(),
                page=page,
                box=box,
                field_name=field_name,
            )
        )

    if all(s.valid for s in signers) and all(s.trusted for s in signers):
        message = _("Verification completed successfully")
        status_key = "valid_trusted"
    elif not all(s.valid for s in signers):
        message = _("The signature is not valid: the document may have been modified")
        status_key = "invalid"
    else:
        message = _("Signature valid, but the certificate chain is not trusted")
        status_key = "valid_untrusted"

    return VerificationReport(
        file_format="PAdES", status=status_key, message=message, signers=signers
    )


async def verify_file(
    path: str, validation_context: Optional[ValidationContext] = None
) -> VerificationReport:
    """Verify a signed file, automatically detecting the format."""
    try:
        with open(path, "rb") as file:
            data = file.read()
    except OSError as exc:
        return VerificationReport(
            file_format="?", status="error", message=str(exc)
        )

    if data.startswith(b"%PDF-"):
        return await verify_pades(data, validation_context)
    return await verify_cades(data, validation_context)