# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Davide Truffa <davide@catoblepa.org>

import sys
import threading
import traceback

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gdk, Gio, Gtk

from signature_viewer.util.i18n import APP_ID
from signature_viewer.ui.main_window import SignaturesWindow

_ERROR_LOG = None


def _install_excepthook():
    """Log unhandled exceptions to a file for debugging."""
    global _ERROR_LOG
    try:
        import os
        from pathlib import Path

        base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
        _ERROR_LOG = Path(base) / "signature-viewer" / "errors.log"
        _ERROR_LOG.parent.mkdir(parents=True, exist_ok=True)
    except Exception:
        _ERROR_LOG = None

    def hook(exc_type, exc_value, exc_tb):
        if _ERROR_LOG is not None:
            try:
                with open(_ERROR_LOG, "a", encoding="utf-8") as f:
                    f.write("".join(traceback.format_exception(exc_type, exc_value, exc_tb)))
            except Exception:
                pass
        sys.__excepthook__(exc_type, exc_value, exc_tb)

    sys.excepthook = hook


def _install_css():
    """Load the application stylesheet with semantic status classes."""
    css = b"""
.status-success { color: @success_color; font-weight: 600; }
.status-warning { color: @warning_color; font-weight: 600; }
.status-error   { color: @error_color; font-weight: 600; }
.status-info    { color: @insensitive_fg_color; font-weight: 600; }
.sig-badge {
  font-size: 11px;
  font-weight: 700;
  padding: 1px 8px;
  border-radius: 999px;
}
.sig-badge-cades { color: @accent_color; background-color: alpha(@accent_bg_color, 0.18); }
.sig-badge-pades { color: @warning_color; background-color: alpha(@warning_bg_color, 0.18); }
"""
    provider = Gtk.CssProvider()
    provider.load_from_data(css)
    Gtk.StyleContext.add_provider_for_display(
        Gdk.Display.get_default(), provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
    )


class SignatureViewerApplication(Adw.Application):
    def __init__(self):
        super().__init__(
            application_id=APP_ID, flags=Gio.ApplicationFlags.HANDLES_OPEN
        )
        self.window = None

    def do_startup(self):
        Adw.Application.do_startup(self)

        open_action = Gio.SimpleAction.new("open", None)
        open_action.connect("activate", self._on_open)
        self.add_action(open_action)

        refresh_action = Gio.SimpleAction.new("refresh-certificates", None)
        refresh_action.connect("activate", self._on_refresh_certificates)
        self.add_action(refresh_action)

        about_action = Gio.SimpleAction.new("about", None)
        about_action.connect("activate", self._on_about)
        self.add_action(about_action)

        quit_action = Gio.SimpleAction.new("quit", None)
        quit_action.connect("activate", lambda *a: self.quit())
        self.add_action(quit_action)

        shortcuts_action = Gio.SimpleAction.new("shortcuts", None)
        shortcuts_action.connect("activate", self._on_shortcuts)
        self.add_action(shortcuts_action)

        open_saved_action = Gio.SimpleAction.new("open-saved-file", None)
        open_saved_action.connect("activate", self._on_open_saved_file)
        self.add_action(open_saved_action)

        self.set_accels_for_action("app.open", ["<Ctrl>o"])
        self.set_accels_for_action("app.quit", ["<Ctrl>q"])
        self.set_accels_for_action("app.shortcuts", ["<Ctrl><Shift>question"])
        self.set_accels_for_action("win.close-window", ["<Ctrl>w"])

        _install_css()
        self._refresh_trust_background()

    def _on_refresh_certificates(self, _action, _parameter):
        if self.window is not None:
            self.window.force_refresh_tsl()

    def _on_about(self, _action, _parameter):
        if self.window is not None:
            self.window.show_about()

    def _on_shortcuts(self, _action, _parameter):
        if self.window is not None:
            self.window.show_shortcuts()

    def _on_open_saved_file(self, _action, _parameter):
        if self.window is not None:
            self.window.open_saved_file()

    def _refresh_trust_background(self):
        """Update the TSL in the background if the cache is stale (at startup)."""

        def work():
            from signature_viewer.core import trust

            trust.load_tsl_roots()

        threading.Thread(target=work, daemon=True).start()

    def do_activate(self):
        if self.window is None:
            self.window = SignaturesWindow(self)
        self.window.present()

    def do_open(self, files, n_files, hint):
        self.do_activate()
        paths = [f.get_path() for f in files if f.get_path()]
        if self.window is not None:
            self.window.open_document(paths[0] if paths else None)

    def _on_open(self, action, parameter):
        if self.window is not None:
            self.window.open_document_dialog()


def main():
    _install_excepthook()
    app = SignatureViewerApplication()
    return app.run(sys.argv)