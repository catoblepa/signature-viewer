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
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
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
from signature_viewer.util import debug
from signature_viewer.util.i18n import _

_logger = logging.getLogger(__name__)

# re-export for compatibility
load_system_trust_roots = trust.load_system_trust_roots
load_trust_roots = trust.load_trust_roots

# Session-wide cache of the validation context. Building it loads the system
# trust anchors and registers hundreds of TSL certificates, which costs on the
# order of half a second and was previously repeated on every document open.
_context_lock = threading.Lock()
_cached_context: Optional[ValidationContext] = None
_cached_at: Optional[datetime] = None
_CONTEXT_MAX_AGE = timedelta(days=7)


def _context_is_fresh() -> bool:
    return (
        _cached_at is not None
        and datetime.now(timezone.utc) - _cached_at < _CONTEXT_MAX_AGE
    )


def get_validation_context() -> ValidationContext:
    """Return the cached validation context, rebuilding it when stale.

    The context is built lazily on first use and reused for subsequent
    verifications, so opening many documents only pays the trust-store setup
    cost once. Call :func:`invalidate_validation_context` after a TSL refresh
    to force a rebuild.
    """
    global _cached_context, _cached_at
    with _context_lock:
        if _cached_context is not None and _context_is_fresh():
            return _cached_context
        context = build_validation_context()
        _cached_context = context
        _cached_at = datetime.now(timezone.utc)
        return context


def invalidate_validation_context() -> None:
    """Discard the cached validation context so it is rebuilt on next use."""
    global _cached_context, _cached_at
    with _context_lock:
        _cached_context = None
        _cached_at = None


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
    revoked: bool = False
    level: int = 1


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
        # Use the cached TSL so building the context never blocks on a network
        # download; the background/startup refresh updates the cache in time.
        trust_roots = trust.load_trust_roots_cached()
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


def _revocation_info_from_status(status) -> tuple[bool, dict]:
    """Return ``(revoked, info_dict)`` from a pyhanko signature status."""
    revoked = bool(getattr(status, "revoked", False))
    info = {}
    if revoked:
        status_value = f"✗ {_('Revoked')}"
        details = getattr(status, "revocation_details", None)
        if details is not None:
            rev_date = getattr(details, "revocation_date", None)
            if rev_date is not None:
                status_value += f" · {rev_date.strftime('%d/%m/%Y %H:%M:%S')}"
        info[_("Certificate status")] = status_value
    return revoked, info


def _untrusted_message(signers: List[SignerReport]) -> str:
    """Choose a clear message when signatures are intact but not trusted.

    ``valid_untrusted`` covers several situations: a revoked certificate, an
    untrusted certificate chain (unknown CA) or a certificate that is no longer
    valid (expired / not yet valid). Pick the most informative wording, giving
    priority to the most severe cause.
    """
    revoked = any(s.revoked for s in signers)
    expired = False
    not_yet_valid = False
    status_key = _("Certificate status")
    for signer in signers:
        cert_status = signer.info.get(status_key, "")
        if _("Expired") in cert_status:
            expired = True
        elif _("Not yet valid") in cert_status:
            not_yet_valid = True
    if revoked:
        return _("The signature is intact, but the certificate has been revoked")
    if expired:
        return _(
            "The signature is intact, but the certificate is expired"
        )
    if not_yet_valid:
        return _(
            "The signature is intact, but the certificate is not yet valid"
        )
    return _("The signature is intact, but the certificate chain is not trusted")


def _invalid_message(signers: List[SignerReport]) -> str:
    """Choose a clear message when one or more signatures are not valid."""
    if len(signers) == 1:
        return _("The signature is not valid: the document may have been modified")
    invalid = sum(1 for signer in signers if not signer.valid)
    return _("Not all signatures are valid (%(invalid)d of %(total)d)") % {
        "invalid": invalid,
        "total": len(signers),
    }


def _signed_data_for_signer(
    signed_data: cms.SignedData, signer_info: cms.SignerInfo
) -> cms.SignedData:
    """Return a copy of ``signed_data`` with a single ``SignerInfo``.

    pyhanko's CMS validation API handles exactly one signer at a time. A
    parallel co-signature (multiple ``SignerInfo`` entries in the same
    ``SignedData``) is valid CMS, so each signer is validated on its own copy.
    """
    single = signed_data.copy()
    single["signer_infos"] = cms.SignerInfos([signer_info.copy()])
    return single


async def _validate_cades_levels(
    data_der: bytes, validation_context: ValidationContext
) -> Tuple[List[SignerReport], Optional[Exception], bool]:
    """Validate every signer of every nested CAdES envelope.

    Returns the per-signer reports, the first validation exception (if any) and
    whether at least one signer could be validated at all.
    """
    signers: List[SignerReport] = []
    first_error: Optional[Exception] = None
    validated_any = False

    for level, signed_data, cert_list in display.iter_livelli_busta(data_der):
        for idx, signer_info in enumerate(signed_data["signer_infos"], 1):
            info = display.mostra_info_firma(signer_info, cert_list)
            info["tipo_firma"] = "CAdES"
            info["firmatario_idx"] = idx
            info["livello_busta"] = level
            try:
                status = await async_validate_cms_signature(
                    _signed_data_for_signer(signed_data, signer_info),
                    validation_context=validation_context,
                )
            except Exception as exc:
                # Report a per-signer failure instead of aborting the whole
                # verification, so the other signatures can still be shown.
                if first_error is None:
                    first_error = exc
                debug.debug(
                    f"CAdES: signer #{idx} (level {level}) failed to validate: {exc}"
                )
                info[_("Error")] = f"{_('Verification error')}: {exc}"
                signers.append(
                    SignerReport(
                        info=info,
                        valid=False,
                        trusted=False,
                        summary="ERROR",
                        level=level,
                    )
                )
                continue

            validated_any = True
            revoked, rev_info = _revocation_info_from_status(status)
            info.update(rev_info)
            # ``status.valid`` only covers the signature over the signed
            # attributes; ``status.intact`` covers the digest of the content.
            # A tampered document is intact=False and must not be reported as
            # a valid signature.
            intact = getattr(status, "intact", True)
            debug.debug(
                f"CAdES: signer #{idx} (level {level}) validated: {status.summary()}"
            )
            signers.append(
                SignerReport(
                    info=info,
                    valid=status.valid and intact,
                    trusted=status.trusted,
                    summary=status.summary(),
                    revoked=revoked,
                    level=level,
                )
            )

    return signers, first_error, validated_any


async def verify_cades(
    data: bytes, validation_context: Optional[ValidationContext] = None
) -> VerificationReport:
    """Verify a CAdES envelope (DER/PEM/Base64), including nested envelopes."""
    if validation_context is None:
        validation_context = get_validation_context()

    _formato, data_der = display.rileva_formato_p7m(data)

    try:
        content_info = cms.ContentInfo.load(data_der)
        if content_info["content_type"].native != "signed_data":
            return _report_no_signatures("CAdES")
    except Exception:
        return _report_no_signatures("CAdES")

    signers, first_error, validated_any = await _validate_cades_levels(
        data_der, validation_context
    )

    if not signers:
        return _report_no_signatures("CAdES")
    if not validated_any and first_error is not None:
        # Every signature failed to validate (e.g. missing signer certificate):
        # surface the error, but keep the signer rows for context.
        return VerificationReport(
            file_format="CAdES",
            status="error",
            message=f"{_('Verification error')}: {first_error}",
            signers=signers,
        )

    if all(s.valid for s in signers) and all(s.trusted for s in signers):
        return VerificationReport(
            file_format="CAdES",
            status="valid_trusted",
            message=_("Verification completed successfully"),
            signers=signers,
        )
    if not all(s.valid for s in signers):
        return VerificationReport(
            file_format="CAdES",
            status="invalid",
            message=_invalid_message(signers),
            signers=signers,
        )
    return VerificationReport(
        file_format="CAdES",
        status="valid_untrusted",
        message=_untrusted_message(signers),
        signers=signers,
    )


def _signer_position(
    signed_data: cms.SignedData, signer_info: cms.SignerInfo
) -> int:
    """Index of ``signer_info`` within ``signed_data``, or 0 if not found."""
    target = signer_info.dump()
    for index, candidate in enumerate(signed_data["signer_infos"]):
        if candidate.dump() == target:
            return index
    return 0


def _pades_signature_valid(status) -> bool:
    """Overall validity of a PDF signature.

    ``valid`` only covers the signature over the signed attributes and
    ``intact`` the digest of the signed document revision; the PDF
    modification policy and seed value constraints must hold as well.
    """
    if not (status.valid and getattr(status, "intact", True)):
        return False
    modification_ok = getattr(status, "docmdp_ok", True) or (
        getattr(status, "modification_level", None) is None
    )
    return modification_ok and getattr(status, "seed_value_ok", True)


async def verify_pades(
    pdf_bytes: bytes, validation_context: Optional[ValidationContext] = None
) -> VerificationReport:
    """Verify the PAdES signatures of a PDF."""
    if validation_context is None:
        validation_context = get_validation_context()

    try:
        # strict=False: some signed PDFs use a hybrid-reference xref table
        # (a classic xref table trailer with a /XRefStm pointing at an xref
        # stream). pyhanko refuses to validate those in strict mode, so we
        # open them leniently; the parallel pypdf extraction already tolerates
        # them.
        reader = PdfFileReader(io.BytesIO(pdf_bytes), strict=False)
        embedded = list(collect_embedded_signatures(reader))
    except Exception as exc:
        debug.debug(f"PAdES: cannot read PDF: {exc}")
        return _report_error("PAdES", exc)

    if not embedded:
        return _report_no_signatures("PAdES")

    pdf_signatures = display.estrai_firme_da_pdf(pdf_bytes)
    debug.debug(f"PAdES: found {len(embedded)} embedded signature(s), "
                f"{len(pdf_signatures)} pypdf-extracted signature(s)")
    signers: List[SignerReport] = []

    for i, embedded_sig in enumerate(embedded):
        try:
            status = await async_validate_pdf_signature(
                embedded_sig, signer_validation_context=validation_context
            )
        except Exception as exc:
            # Report a per-signer failure instead of aborting the whole
            # verification, so other signatures can still be shown.
            debug.debug(f"PAdES: signer #{i} failed to validate: {exc}")
            sig_field = getattr(embedded_sig, "sig_field", None)
            field_name = ""
            if sig_field is not None:
                try:
                    field_name = str(sig_field.get("/T") or "")
                except Exception:
                    pass
            signers.append(
                SignerReport(
                    info={_("Error"): f"{_('Verification error')}: {exc}"},
                    valid=False,
                    trusted=False,
                    summary="ERROR",
                    field_name=field_name,
                )
            )
            continue

        info = {}
        if status.signing_cert is not None:
            subject = status.signing_cert.subject
            info[_("Identity")] = display.estrai_nome_cognome(subject)
            info[_("Tax Code")] = display.estrai_codice_fiscale(subject)
            info[_("Organization")] = display.estrai_organization(subject)
            info[_("Certificate issued by")] = (
                status.signing_cert.issuer.human_friendly
            )
        revoked, rev_info = _revocation_info_from_status(status)
        info.update(rev_info)
        debug.debug(f"PAdES: signer #{i} validated: {status.summary()}")

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
                # A single PDF signature may carry multiple SignerInfo entries;
                # pick the one being validated instead of always the first.
                position = _signer_position(
                    embedded_sig.signed_data, embedded_sig.signer_info
                )
                if position >= len(parsed):
                    position = 0
                info = {**parsed[position], **info}
            if matched.get("reason"):
                info[_("Reason")] = matched["reason"]
            if matched.get("location"):
                info[_("Location")] = matched["location"]

        signers.append(
            SignerReport(
                info=info,
                valid=_pades_signature_valid(status),
                trusted=status.trusted,
                summary=status.summary(),
                page=page,
                box=box,
                field_name=field_name,
                revoked=revoked,
            )
        )

    if all(s.valid for s in signers) and all(s.trusted for s in signers):
        message = _("Verification completed successfully")
        status_key = "valid_trusted"
    elif not all(s.valid for s in signers):
        message = _invalid_message(signers)
        status_key = "invalid"
    else:
        message = _untrusted_message(signers)
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