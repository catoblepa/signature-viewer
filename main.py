#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Davide Truffa <davide@catoblepa.org>

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from signature_viewer.app import main

if __name__ == "__main__":
    sys.exit(main())