# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Davide Truffa <davide@catoblepa.org>

import logging
import os
import shlex
import subprocess
from pathlib import Path

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gdk, Gio, GLib, Gtk

from signature_viewer.util.i18n import APP_ID, _

for _name in ("pyhanko", "pyhanko_certvalidator"):
    logging.getLogger(_name).setLevel(logging.CRITICAL)

BLUEPRINTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "blueprints")
APP_ICON_NAME = "io.github.catoblepa.signature-viewer"
_DEBUG = os.environ.get("SIGNATURE_VIEWER_DEBUG", "").lower() in {
    "1", "true", "yes", "on"
}


def _debug(message):
    if _DEBUG:
        print(f"[signature-viewer][debug] {message}", flush=True)

_ICON_SOURCE_DIR = os.path.abspath(
    os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "..", "data", "icons"
    )
)


def _data_ui_dirs():
    """Directories where the compiled .ui files are searched (installation)."""
    base = os.path.dirname(os.path.abspath(__file__))
    return [
        os.path.abspath(
            os.path.join(base, "..", "..", "..", "..", "share", "signature-viewer", "ui")
        ),
        "/app/share/signature-viewer/ui",
    ]


def _compile_blueprint(name):
    """Compile a .blp file into XML .ui (development fallback)."""
    blp_path = Path(BLUEPRINTS_DIR) / f"{name}.blp"
    try:
        from blueprintcompiler.main import BlueprintApp

        xml, _warnings = BlueprintApp()._compile(blp_path.read_text())
        return xml
    except ImportError:
        raise RuntimeError(
            "blueprint-compiler non disponibile e nessun file .ui compilato per "
            f"{name}.blp"
        )


def _load_builder(name):
    builder = Gtk.Builder()
    builder.set_translation_domain(APP_ID)

    candidates = [Path(d) / f"{name}.ui" for d in _data_ui_dirs()]
    candidates.append(Path(BLUEPRINTS_DIR) / f"{name}.ui")
    candidates.append(Path(BLUEPRINTS_DIR) / f"{name}.blp")

    for candidate in candidates:
        if not candidate.exists():
            continue
        if candidate.suffix == ".ui":
            builder.add_from_file(str(candidate))
        else:
            builder.add_from_string(_compile_blueprint(name))
        return builder

    raise RuntimeError(f"nessuna risorsa UI trovata per {name}")


def _human_size(num_bytes: int) -> str:
    size = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{num_bytes} B"


def _is_pdf(path: str) -> bool:
    try:
        with open(path, "rb") as file:
            return file.read(5) == b"%PDF-"
    except OSError:
        return False


def _detect_file_kind(path: str) -> str:
    if _is_pdf(path):
        return _("PDF document")
    return _("File")


def _initial_width() -> int:
    """Startup window width."""
    return 600


def _initial_height() -> int:
    """Startup window height."""
    return 500


_PREVIEW_WIDTH = 1100
_PREVIEW_HEIGHT = 720


class SignaturesWindow(Adw.ApplicationWindow):
    def __init__(self, app):
        super().__init__(application=app)
        self.set_title(_("Signature Viewer"))
        self.set_icon_name(APP_ICON_NAME)
        self.set_default_size(_initial_width(), _initial_height())
        if os.path.isdir(_ICON_SOURCE_DIR):
            theme = Gtk.IconTheme.get_for_display(self.get_display())
            theme.add_search_path(_ICON_SOURCE_DIR)

        builder = _load_builder("main_window")
        self.toast_overlay = Adw.ToastOverlay()
        self.toast_overlay.set_child(builder.get_object("main_toolbar"))
        self.set_content(self.toast_overlay)

        self.btn_open = builder.get_object("btn_open")
        self.menu_button = builder.get_object("menu_button")
        self.stack_main = builder.get_object("stack_main")
        self.empty_state = builder.get_object("empty_state")
        self.document_view = builder.get_object("document_view")
        self.file_icon = builder.get_object("file_icon")
        self.file_name = builder.get_object("file_name")
        self.file_meta = builder.get_object("file_meta")
        self.verify_status = builder.get_object("verify_status")
        self.verify_list = builder.get_object("verify_list")
        self.btn_open_extracted = builder.get_object("btn_open_extracted")
        self.btn_open_extracted_icon = builder.get_object("btn_open_extracted_icon")
        self.btn_open_extracted_label = builder.get_object("btn_open_extracted_label")
        self.pdf_panel = builder.get_object("pdf_panel")
        self.pdf_scroll = builder.get_object("pdf_scroll")
        self.btn_pdf_prev = builder.get_object("btn_pdf_prev")
        self.btn_pdf_next = builder.get_object("btn_pdf_next")
        self.btn_zoom_in = builder.get_object("btn_zoom_in")
        self.btn_zoom_out = builder.get_object("btn_zoom_out")
        self.lbl_pdf_page = builder.get_object("lbl_pdf_page")

        self.current_path = None
        self.current_is_pdf = False
        self._extracted_content = None
        self._extracted_name = None
        self._extracted_is_pdf = False
        self._expand_rows = []
        self._pdf_preview = None
        self._saved_path = None

        close_action = Gio.SimpleAction.new("close-window", None)
        close_action.connect("activate", lambda *a: self.close())
        self.add_action(close_action)

        self.btn_open_extracted.connect("clicked", self._on_open_extracted_clicked)
        self.btn_pdf_prev.connect("clicked", self._on_pdf_prev_clicked)
        self.btn_pdf_next.connect("clicked", self._on_pdf_next_clicked)
        self.btn_zoom_in.connect("clicked", self._on_zoom_in_clicked)
        self.btn_zoom_out.connect("clicked", self._on_zoom_out_clicked)
        self.verify_list.connect("row-selected", self._on_row_selected)

        self._setup_drag_drop()
        self._setup_menu()

    # --- drag & drop / menu ---

    def _setup_drag_drop(self):
        drop_target = Gtk.DropTarget.new(Gio.File, Gdk.DragAction.COPY)
        drop_target.connect("drop", self._on_file_drop)
        self.add_controller(drop_target)

    def _on_file_drop(self, _target, value, _x, _y):
        if not value:
            return False
        path = value.get_path()
        if not path or not os.access(path, os.R_OK):
            self._show_toast(_("File not accessible"))
            return False
        self.open_document(path)
        return True

    def _setup_menu(self):
        menu = Gio.Menu()
        menu.append(_("Update certificates (TSL)"), "app.refresh-certificates")
        menu.append(_("Keyboard Shortcuts"), "app.shortcuts")
        menu.append(_("About"), "app.about")
        menu.append(_("Quit"), "app.quit")
        self.menu_button.set_menu_model(menu)

    def _show_toast(self, text):
        toast = Adw.Toast.new(text)
        self.toast_overlay.add_toast(toast)

    def force_refresh_tsl(self):
        import threading

        from signature_viewer.core import trust

        self._show_toast(_("Updating certificates…"))

        def work():
            roots = trust.refresh_tsl_roots()
            GLib.idle_add(self._on_tsl_refresh_done, roots)

        threading.Thread(target=work, daemon=True).start()

    def _on_tsl_refresh_done(self, roots):
        if roots is None:
            self._show_toast(f"⚠ {_('Certificate update failed')}")
        else:
            self._show_toast(f"✓ {_('Certificates updated')}: {len(roots)}")

    def show_about(self):
        from signature_viewer import __version__

        about = Adw.AboutWindow(transient_for=self)
        about.set_application_name(_("Signature Viewer"))
        about.set_icon_name(APP_ICON_NAME)
        about.set_version(__version__)
        about.set_developer_name("Davide Truffa")
        about.set_license_type(Gtk.License.GPL_3_0)
        about.set_comments(
            _("Verification of digital signatures (PAdES/CAdES) with in-app preview")
        )
        about.add_credit_section("Icons", ["Andrej Koelewijn"])
        about.present()

    # --- document ---

    def open_document_dialog(self):
        dialog = Gtk.FileDialog()
        dialog.set_title(_("Open document"))
        filters = Gio.ListStore.new(Gtk.FileFilter)

        filter_signed = Gtk.FileFilter()
        filter_signed.set_name(_("Signed files (.p7m, .pdf)"))
        filter_signed.add_pattern("*.p7m")
        filter_signed.add_pattern("*.P7M")
        filter_signed.add_pattern("*.p7s")
        filter_signed.add_pattern("*.P7S")
        filter_signed.add_pattern("*.pdf")
        filter_signed.add_pattern("*.PDF")
        filters.append(filter_signed)

        filter_all = Gtk.FileFilter()
        filter_all.set_name(_("All files"))
        filter_all.add_pattern("*")
        filters.append(filter_all)

        dialog.set_filters(filters)
        dialog.open(self, None, self._on_document_open)

    def _on_document_open(self, dialog, result):
        try:
            file = dialog.open_finish(result)
        except GLib.Error:
            return
        self.open_document(file.get_path())

    def _set_original_action(self, save: bool):
        """Configure the header action: open (PDF) or save (extracted content)."""
        if save:
            self.btn_open_extracted_icon.set_from_icon_name("document-save-symbolic")
            self.btn_open_extracted_label.set_label(_("Save original document"))
            self.btn_open_extracted.set_tooltip_text(_("Save original document"))
        else:
            self.btn_open_extracted_icon.set_from_icon_name("document-open-symbolic")
            self.btn_open_extracted_label.set_label(_("Open document"))
            self.btn_open_extracted.set_tooltip_text(_("Open document"))

    def open_document(self, path):
        if not path:
            return
        self.current_path = path
        self.current_is_pdf = _is_pdf(path)
        self._extracted_content = None
        self._extracted_name = None
        self._extracted_is_pdf = False
        self._set_status("", "")
        self._clear_verify_list()
        self._clear_pdf_preview()

        name = os.path.basename(path)
        try:
            size = os.path.getsize(path)
        except OSError:
            size = 0
        kind = _detect_file_kind(path)

        self.file_icon.set_from_icon_name(
            "x-office-document-symbolic" if self.current_is_pdf else "text-x-generic-symbolic"
        )
        self.file_name.set_text(name)
        self.file_meta.set_text(f"{kind} · {_human_size(size)}")

        self._set_original_action(save=not self.current_is_pdf)
        self.btn_open_extracted.set_sensitive(False)
        self.stack_main.set_visible_child(self.document_view)
        self._verify_current_document()

    def _clear_verify_list(self):
        while (row := self.verify_list.get_first_child()) is not None:
            self.verify_list.remove(row)
        self._expand_rows = []

    def _clear_pdf_preview(self):
        self.pdf_panel.set_visible(False)
        if self._pdf_preview is not None:
            self.pdf_scroll.set_child(None)
            self._pdf_preview = None

    def _set_status(self, text, css_class):
        for cls in ("status-success", "status-warning", "status-error", "status-info"):
            self.verify_status.remove_css_class(cls)
        if css_class:
            self.verify_status.add_css_class(css_class)
        self.verify_status.set_text(text)

    # --- verification ---

    def _verify_current_document(self):
        from signature_viewer.core.verify import verify_file
        from signature_viewer.util.async_runner import run_coroutine

        path = self.current_path
        self._set_status(_("Verifying…"), "status-info")

        run_coroutine(
            lambda: verify_file(path),
            self._on_verify_done,
            self._on_verify_error,
        )

    def _on_verify_error(self, error):
        self._set_status(f"✗ {_('Verification error')}: {error}", "status-error")

    def _on_verify_done(self, report):
        if report is None:
            return
        self._show_verification_report(report)

    def _show_verification_report(self, report):
        status_key = report.status
        if status_key == "valid_trusted":
            self._set_status(f"✓ {report.message}", "status-success")
        elif status_key == "valid_untrusted":
            self._set_status(f"⚠ {report.message}", "status-warning")
        elif status_key == "invalid":
            self._set_status(f"✗ {report.message}", "status-error")
        elif status_key == "no_signatures":
            self._set_status(f"ℹ {report.message}", "status-info")
        else:
            self._set_status(f"✗ {report.message}", "status-error")

        self._clear_verify_list()
        for index, signer in enumerate(report.signers):
            self._expand_rows.append(self._make_signer_expander(signer, report.file_format))
            self.verify_list.append(self._expand_rows[-1])

        is_pades = report.file_format == "PAdES"

        if is_pades:
            self._setup_pdf_preview(report)
            self._set_original_action(save=False)
            if report.signers:
                self.btn_open_extracted.set_sensitive(True)
        else:
            self._clear_pdf_preview()
            from signature_viewer.core import display

            with open(self.current_path, "rb") as file:
                raw = file.read()
            content = self._estrai_contenuto_innermost(raw)
            if content is not None:
                self._extracted_content = content
                self._extracted_name = self._strip_signature_suffix(
                    os.path.basename(self.current_path)
                )
                self._extracted_is_pdf = content.startswith(b"%PDF")
                self._set_original_action(save=not self._extracted_is_pdf)
                self.btn_open_extracted.set_sensitive(True)

    def _make_signer_expander(self, signer, file_format):
        from signature_viewer.core import display

        info = signer.info
        identity = info.get(_("Identity")) or info.get(_("Error")) or _("Unknown signer")

        badge = Gtk.Label(label=file_format)
        badge.add_css_class("sig-badge")
        badge.add_css_class(
            "sig-badge-pades" if file_format == "PAdES" else "sig-badge-cades"
        )

        expander = Adw.ExpanderRow()
        expander.set_title(str(identity))
        expander.set_subtitle(self._signer_subtitle(signer))
        expander.add_prefix(badge)

        for key, value in info.items():
            if key in ("tipo_firma", "firmatario_idx", "livello_busta"):
                continue
            row = Adw.ActionRow()
            row.set_title(str(key))
            row.set_subtitle(str(value))
            row.set_selectable(False)
            expander.add_row(row)

        if signer.summary:
            row = Adw.ActionRow()
            row.set_title(_("Verification summary"))
            row.set_subtitle(signer.summary)
            row.set_selectable(False)
            expander.add_row(row)

        if signer.page is not None:
            row = Adw.ActionRow()
            row.set_title(_("Signature field"))
            row.set_subtitle(
                signer.field_name or f"{_('Page')} {signer.page + 1}"
            )
            row.set_selectable(False)
            expander.add_row(row)

        return expander

    def _signer_subtitle(self, signer):
        parts = []
        parts.append(
            ("✓ " if signer.valid else "✗ ") + (_("Valid") if signer.valid else _("Invalid"))
        )
        parts.append(
            ("✓ " if signer.trusted else "⚠ ")
            + (_("Trusted") if signer.trusted else _("Not trusted"))
        )
        return " · ".join(parts)

    def _estrai_contenuto_innermost(self, raw: bytes):
        """Extract the innermost content from a (possibly nested) .p7m."""
        from asn1crypto import cms

        from signature_viewer.core import display

        current = raw
        for _ in range(12):
            content = display.estrai_contenuto_p7m(current)
            if content is None:
                return current
            try:
                ci = cms.ContentInfo.load(content)
                if ci["content_type"].native != "signed_data":
                    return content
            except Exception:
                return content
            current = content
        return current

    def _strip_signature_suffix(self, name: str) -> str:
        lower = name.lower()
        for suffix in (".p7m", ".p7s", ".p7c", ".p7b"):
            if lower.endswith(suffix):
                return name[: -len(suffix)]
        return name

    # --- PDF preview ---

    def _setup_pdf_preview(self, report):
        try:
            from signature_viewer.ui.widgets.pdf_preview import PdfPreview

            preview = PdfPreview(self.current_path)
        except Exception as exc:
            self._show_toast(f"⚠ {_('PDF preview unavailable')}: {exc}")
            self._clear_pdf_preview()
            return

        signatures = []
        for index, signer in enumerate(report.signers):
            if signer.box is None or signer.page is None:
                continue
            label = (
                signer.field_name
                or signer.info.get(_("Identity"))
                or f"{_('Signature')} {index + 1}"
            )
            signatures.append(
                {
                    "page": signer.page,
                    "box": signer.box,
                    "label": str(label),
                }
            )
        preview.set_signatures(signatures)

        self._pdf_preview = preview
        self.pdf_scroll.set_child(preview)
        self.pdf_panel.set_visible(True)
        self.set_default_size(_PREVIEW_WIDTH, _PREVIEW_HEIGHT)
        self._update_pdf_page_label()

        preview.connect("signature-activated", self._on_signature_activated)

    def _update_pdf_page_label(self):
        if self._pdf_preview is None:
            return
        total = self._pdf_preview.page_count
        current = self._pdf_preview.current_page + 1
        self.lbl_pdf_page.set_text(f"{current} / {total}")

    def _on_pdf_prev_clicked(self, _button):
        if self._pdf_preview is not None:
            self._pdf_preview.prev_page()
            self._update_pdf_page_label()

    def _on_pdf_next_clicked(self, _button):
        if self._pdf_preview is not None:
            self._pdf_preview.next_page()
            self._update_pdf_page_label()

    def _on_zoom_in_clicked(self, _button):
        if self._pdf_preview is not None:
            self._pdf_preview.zoom_in()

    def _on_zoom_out_clicked(self, _button):
        if self._pdf_preview is not None:
            self._pdf_preview.zoom_out()

    def _on_signature_activated(self, _preview, index):
        if 0 <= index < len(self._expand_rows):
            row = self._expand_rows[index]
            row.set_expanded(True)
            self.verify_list.select_row(row)

    def _on_row_selected(self, _listbox, row):
        if row is None or self._pdf_preview is None:
            return
        if row in self._expand_rows:
            index = self._expand_rows.index(row)
            self._pdf_preview.goto_signature(index)

    # --- original document action ---

    def _on_open_extracted_clicked(self, _button):
        if self.current_is_pdf:
            self._open_pdf(self.current_path)
            return
        if self._extracted_is_pdf and self._extracted_content is not None:
            self._open_extracted_pdf()
            return
        self._save_original_document()

    def _open_extracted_pdf(self):
        """Write the extracted PDF to Downloads and open it."""
        name = self._extracted_name or "document"
        if not name.lower().endswith(".pdf"):
            name += ".pdf"
        shared = self._write_shared_copy(name)
        if shared is not None:
            self._open_pdf(shared)
        else:
            self._save_original_document()

    def _write_shared_copy(self, name: str):
        """Write the content to the shared Downloads directory.

        Returns the real shared path, or None when unavailable. The dialog path
        returned by Gtk.FileDialog can be a document-portal path that external
        applications cannot resolve, so we always keep a copy in Downloads.
        """
        downloads = GLib.get_user_special_dir(GLib.UserDirectory.DIRECTORY_DOWNLOAD)
        _debug(f"get_user_special_dir(DOWNLOAD) -> {downloads!r}")
        if not downloads:
            return None
        try:
            os.makedirs(downloads, exist_ok=True)
        except OSError as exc:
            _debug(f"cannot create downloads dir: {exc}")
            return None
        path = os.path.join(downloads, name)
        try:
            with open(path, "wb") as out:
                out.write(self._extracted_content)
            _debug(f"wrote shared copy {path} ({len(self._extracted_content)} bytes)")
            return path
        except OSError as exc:
            _debug(f"cannot write shared copy {path}: {exc}")
            return None

    def _open_pdf(self, path):
        if not path or not os.path.exists(path):
            self._show_toast(_("File opening error"))
            return
        gfile = Gio.File.new_for_path(path)
        launcher = Gtk.FileLauncher.new(gfile)
        launcher.launch(self, None, self._on_pdf_launch_done)

    def _on_pdf_launch_done(self, launcher, result):
        try:
            launcher.launch_finish(result)
        except GLib.Error:
            self._show_toast(_("File opening error"))

    def _save_original_document(self):
        if self._extracted_content is None:
            return
        dialog = Gtk.FileDialog()
        dialog.set_title(_("Save original document"))
        dialog.set_initial_name(self._extracted_name or "document")
        dialog.save(self, None, self._on_save_done)

    def _on_save_done(self, dialog, result):
        try:
            file = dialog.save_finish(result)
        except GLib.Error:
            return
        chosen = file.get_path()
        _debug(f"save dialog chose: {chosen!r}")
        if self._extracted_content is None:
            _debug("no extracted content to save")
            return
        name = self._extracted_name or "document"
        shared = self._write_shared_copy(name)
        if shared is not None:
            self._show_saved_toast(shared)
            return

        # No shared location available: report clearly instead of using a
        # document-portal path that cannot be reopened.
        _debug(f"no shared location; chosen={chosen!r}")
        self._show_toast(f"⚠ {_('Error saving file')}: {chosen}")

    def _show_saved_toast(self, path: str):
        """Show a toast confirming the save, with an action to open the file."""
        _debug(f"show_saved_toast path={path!r}")
        toast = Adw.Toast.new(f"✓ {_('File saved successfully')}")
        toast.set_button_label(_("_Apri"))
        toast.set_action_name("app.open-saved-file")
        self._saved_path = path
        self.toast_overlay.add_toast(toast)

    def open_saved_file(self):
        """Open the file saved through the last save action."""
        path = getattr(self, "_saved_path", None)
        _debug(f"open_saved_file path={path!r}")
        is_portal = bool(path and path.startswith("/run/user/") and "/doc/" in path)
        if not path or not os.path.exists(path) or is_portal:
            _debug(f"rejected path (exists={path and os.path.exists(path)}, portal={is_portal})")
            self._show_toast(_("File opening error"))
            return

        if self._open_shared_file(path):
            return

        gfile = Gio.File.new_for_path(path)
        launcher = Gtk.FileLauncher.new(gfile)
        launcher.launch(self, None, self._on_pdf_launch_done)

    def _open_shared_file(self, path: str) -> bool:
        """Open a shared saved file without exporting it through OpenURI.

        LibreOffice Flatpak cannot resolve the temporary ``/run/user/.../doc``
        path produced by OpenURI. Launch a Flatpak default handler on the host
        with explicit access to the shared Downloads directory instead.
        """
        if os.environ.get("FLATPAK_ID") != APP_ID:
            return False

        content_type, _uncertain = Gio.content_type_guess(path, None)
        is_calc = content_type in (
            "text/csv",
            "application/vnd.ms-excel",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "application/vnd.oasis.opendocument.spreadsheet",
        ) or path.lower().endswith((".csv", ".xls", ".xlsx", ".ods"))

        if is_calc:
            # GIO may not expose the host's MIME association inside the
            # sandbox, even when LibreOffice is installed on the host.
            app_id = "org.libreoffice.LibreOffice"
        else:
            app = Gio.AppInfo.get_default_for_type(content_type, False)
            commandline = app.get_commandline() if app is not None else ""
            if not commandline or "flatpak" not in commandline:
                return False
            try:
                tokens = shlex.split(commandline)
            except ValueError:
                return False
            app_id = next(
                (
                    token
                    for token in tokens
                    if token.startswith("org.") and "." in token and not token.endswith(".desktop")
                ),
                None,
            )
            if not app_id:
                return False

        args = [
            "flatpak-spawn",
            "--host",
            "flatpak",
            "run",
            "--filesystem=xdg-download",
            app_id,
        ]
        if is_calc:
            args.append("--calc")
        args.append(path)

        _debug(f"host launcher: {args!r}")
        try:
            subprocess.Popen(args, start_new_session=True)
        except OSError as exc:
            _debug(f"host launcher failed: {exc}")
            return False
        return True

    # --- shortcuts ---

    def show_shortcuts(self):
        window = Gtk.ShortcutsWindow(transient_for=self)
        window.set_title(_("Keyboard Shortcuts"))

        section = Gtk.ShortcutsSection()
        group = Gtk.ShortcutsGroup(title=_("General"))
        for title, accel in (
            (_("Open document"), "<Control>o"),
            (_("Close window"), "<Control>w"),
            (_("Quit"), "<Control>q"),
            (_("Keyboard Shortcuts"), "<Control>question"),
        ):
            shortcut = Gtk.ShortcutsShortcut(title=title, accelerator=accel)
            group.add_shortcut(shortcut)
        section.add_group(group)
        window.add_section(section)
        window.present()
