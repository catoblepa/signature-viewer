# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Davide Truffa <davide@catoblepa.org>

"""Command-line verification of a signed file (no GUI required).

Usage::

    python -m signature_viewer.cli <signed-file>
"""
from __future__ import annotations

import asyncio
import logging
import sys

for _name in ("pyhanko", "pyhanko_certvalidator"):
    logging.getLogger(_name).setLevel(logging.CRITICAL)

from signature_viewer.core.verify import verify_file  # noqa: E402

_SKIP_KEYS = ("tipo_firma", "firmatario_idx", "livello_busta")


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) != 1:
        print("Usage: python -m signature_viewer.cli <signed-file>", file=sys.stderr)
        return 2

    report = asyncio.run(verify_file(argv[0]))

    print(f"Format : {report.file_format}")
    print(f"Status : {report.status}")
    print(f"Message: {report.message}")

    for index, signer in enumerate(report.signers, 1):
        print(f"\n--- Signer {index} ---")
        for key, value in signer.info.items():
            if key not in _SKIP_KEYS:
                print(f"  {key}: {value}")
        print(f"  valid  = {signer.valid}")
        print(f"  trusted= {signer.trusted}")
        if signer.page is not None:
            print(f"  page   = {signer.page}")
            print(f"  box    = {signer.box}")
            print(f"  field  = {signer.field_name}")

    return 0


if __name__ == "__main__":
    sys.exit(main())