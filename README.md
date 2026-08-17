# Signature Viewer

**Signature Viewer** is a GNOME application (GTK4 + libadwaita) to open digitally
signed files and verify the contained digital signatures. It follows the GNOME
Human Interface Guidelines.

It is a **verification-only** tool: no signing functionality is included.

- **App ID:** `io.github.catoblepa.signature-viewer`
- **License:** GPL-3.0-or-later
- **Author:** Davide Truffa <davide@catoblepa.org>

## Features

- Open `.p7m` (CAdES) and `.pdf` (PAdES) signed files via file dialog,
  drag & drop, or double click from the file manager.
- Verify each signature: cryptographic validity, document integrity, trust
  chain and certificate status.
- Full signer details: name, tax code, organization, certificate validity,
  signing time, validity at signing time.
- **In-app PDF preview** (Poppler) showing **where each signature was applied**:
  highlighted rectangles, clickable, with page navigation and zoom.
- Multiple and nested signatures (`.p7m.p7m`) support.
- Save the original document contained in a CAdES envelope (or open the PDF
  directly for PAdES files).
- Trust chain validation using the system trust store (p11-kit-trust) plus the
  European Trusted Service List (TSL), refreshed in the background.
- 100% Python verification via [pyhanko](https://github.com/MatthiasValentin/pyhanko)
  (no OpenSSL CLI dependency).
- Internationalized (Italian/English).


## Run from source

```bash
make run          # python3 main.py
```

You can also pass a file directly:

```bash
python3 main.py document.p7m
```

## Install

```bash
make install PREFIX=/usr/local   # or any writable prefix
```

## Flatpak build

The app is packaged as a Flatpak targeting the GNOME 50 runtime:

```bash
flatpak-builder --user --install --force-clean build-dir io.github.catoblepa.signature-viewer.json
```

## Debug

Unhandled exceptions are logged to
`$XDG_CACHE_HOME/signature-viewer/errors.log`.

To enable diagnostic output for the save/open workflow:

```bash
SIGNATURE_VIEWER_DEBUG=1 flatpak run io.github.catoblepa.signature-viewer
```
