# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Davide Truffa <davide@catoblepa.org>

"""Regression tests for parallel and nested CAdES signatures.

The fixtures are generated at test time with the OpenSSL CLI, so no binary
sample files are stored in the repository. Tests are skipped when OpenSSL is
not available.
"""
from __future__ import annotations

import asyncio
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from asn1crypto import x509
from cryptography import x509 as pyca_x509
from cryptography.hazmat.primitives.serialization import Encoding
from pyhanko_certvalidator import ValidationContext
from pyhanko_certvalidator.registry import SimpleCertificateStore

from signature_viewer.core import display
from signature_viewer.core.verify import verify_cades
from signature_viewer.util.i18n import _

CONTENT = b"UNIQUE-CONTENT-PAYLOAD-1234567890"


@unittest.skipUnless(shutil.which("openssl"), "openssl not available")
class CadesVerificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.dir = Path(cls._tmp.name)

        for index in (1, 2, 3):
            cls._openssl(
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-keyout",
                str(cls.dir / f"key{index}.pem"),
                "-out",
                str(cls.dir / f"cert{index}.pem"),
                "-days",
                "3650",
                "-nodes",
                "-subj",
                f"/CN=Test Signer {index}/O=Test",
            )

        content = cls.dir / "content.txt"
        content.write_bytes(CONTENT)

        cls.multi = cls.dir / "multi.p7m"
        cls._openssl(
            "cms",
            "-sign",
            "-nodetach",
            "-binary",
            "-in",
            str(content),
            "-signer",
            str(cls.dir / "cert1.pem"),
            "-inkey",
            str(cls.dir / "key1.pem"),
            "-signer",
            str(cls.dir / "cert2.pem"),
            "-inkey",
            str(cls.dir / "key2.pem"),
            "-outform",
            "DER",
            "-out",
            str(cls.multi),
        )

        # SignerIdentifier = subjectKeyIdentifier instead of
        # issuerAndSerialNumber (OpenSSL's -keyid switch).
        cls.ski = cls.dir / "ski.p7m"
        cls._openssl(
            "cms",
            "-sign",
            "-nodetach",
            "-binary",
            "-keyid",
            "-in",
            str(content),
            "-signer",
            str(cls.dir / "cert1.pem"),
            "-inkey",
            str(cls.dir / "key1.pem"),
            "-outform",
            "DER",
            "-out",
            str(cls.ski),
        )

        cls.nested = cls.dir / "nested.p7m"
        cls._sign_outer(cls.multi, cls.nested, 3)

        # Tamper the inner envelope, then sign the tampered bytes with the
        # outer key: the outer signature is valid, the inner ones are not.
        tampered = cls.dir / "multi_tampered.p7m"
        tampered.write_bytes(
            cls.multi.read_bytes().replace(CONTENT, CONTENT[:-1] + b"X")
        )
        cls.nested_tampered = cls.dir / "nested_tampered.p7m"
        cls._sign_outer(tampered, cls.nested_tampered, 3)

        store = SimpleCertificateStore()
        for index in (1, 2, 3):
            pem = (cls.dir / f"cert{index}.pem").read_bytes()
            der = pyca_x509.load_pem_x509_certificate(pem).public_bytes(
                Encoding.DER
            )
            store.register(x509.Certificate.load(der))
        cls.context = ValidationContext(
            trust_roots=store, allow_fetching=False
        )

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    @classmethod
    def _openssl(cls, *args: str) -> None:
        try:
            subprocess.run(
                ["openssl", *args],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except subprocess.CalledProcessError as exc:
            raise unittest.SkipTest(f"openssl fixture generation failed: {exc}")

    @classmethod
    def _sign_outer(cls, source: Path, destination: Path, index: int) -> None:
        cls._openssl(
            "cms",
            "-sign",
            "-nodetach",
            "-binary",
            "-in",
            str(source),
            "-signer",
            str(cls.dir / f"cert{index}.pem"),
            "-inkey",
            str(cls.dir / f"key{index}.pem"),
            "-outform",
            "DER",
            "-out",
            str(destination),
        )

    def _verify(self, path: Path):
        return asyncio.run(verify_cades(path.read_bytes(), self.context))

    def test_parallel_signatures_are_all_validated(self):
        report = self._verify(self.multi)

        self.assertEqual(report.status, "valid_trusted")
        self.assertEqual(len(report.signers), 2)
        self.assertEqual([signer.level for signer in report.signers], [1, 1])
        self.assertTrue(
            all(signer.valid and signer.trusted for signer in report.signers)
        )

    def test_nested_signatures_are_validated_at_every_level(self):
        report = self._verify(self.nested)

        self.assertEqual(report.status, "valid_trusted")
        self.assertEqual(len(report.signers), 3)
        self.assertEqual([signer.level for signer in report.signers], [1, 2, 2])
        self.assertTrue(
            all(signer.valid and signer.trusted for signer in report.signers)
        )

    def test_tampered_inner_envelope_is_reported_invalid(self):
        report = self._verify(self.nested_tampered)

        self.assertEqual(report.status, "invalid")
        self.assertEqual(len(report.signers), 3)
        outer, *inner = report.signers
        self.assertEqual(outer.level, 1)
        self.assertTrue(outer.valid)
        self.assertTrue(all(signer.level == 2 for signer in inner))
        self.assertTrue(all(not signer.valid for signer in inner))

    def test_subject_key_identifier_signer_is_resolved(self):
        entries = display.analizza_busta(self.ski.read_bytes())
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].get(_("Identity")), "Test Signer 1")

        report = self._verify(self.ski)
        self.assertEqual(report.status, "valid_trusted")
        self.assertTrue(report.signers[0].valid)

    def test_display_lists_every_signer_with_its_level(self):
        entries = display.analizza_busta(self.nested.read_bytes())

        self.assertEqual(len(entries), 3)
        self.assertEqual(
            [entry["livello_busta"] for entry in entries], [1, 2, 2]
        )


if __name__ == "__main__":
    unittest.main()
