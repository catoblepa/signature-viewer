# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Davide Truffa <davide@catoblepa.org>

"""In-app PDF preview with clickable highlighted signature rectangles.

Renders the PDF pages via Poppler into a ``Gtk.DrawingArea`` and overlays the
signature rectangles (from pyhanko ``sig_field.box`` or pypdf ``/Rect``). The
rectangles are clickable and emit the ``signature-activated`` signal.

Rendering is performed on a dedicated worker thread so a complex or large PDF
never blocks the GUI thread; the finished surface is handed back to the GUI
via ``GLib.idle_add``.
"""
from __future__ import annotations

import logging
import os
import threading

import cairo
import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Poppler", "0.18")
from gi.repository import GObject, Gtk, Poppler  # noqa: E402

from signature_viewer.util.i18n import _  # noqa: E402

_logger = logging.getLogger(__name__)

FIT_WIDTH = 760.0
MIN_ZOOM = 0.25
MAX_ZOOM = 4.0
HIT_TOLERANCE = 6.0


class _RenderRequest:
    """A unit of work for the render worker thread."""

    __slots__ = ("page_index", "zoom", "on_ready")

    def __init__(self, page_index: int, zoom: float, on_ready):
        self.page_index = page_index
        self.zoom = zoom
        self.on_ready = on_ready


class _RenderWorker(threading.Thread):
    """Owns the Poppler document and renders pages off the GUI thread.

    All access to the Poppler ``Document`` happens on this single thread, which
    avoids cross-thread use of Poppler objects.
    """

    def __init__(self, uri: str):
        super().__init__(daemon=True)
        self._uri = uri
        self._doc: Poppler.Document | None = None
        self._cond = threading.Condition()
        self._pending: _RenderRequest | None = None
        self._stop = False
        self._page_w = 612.0
        self._page_h = 792.0
        self._base_scale = 1.0
        self._page_count = 0

    def start_document(self) -> bool:
        """Open the document and gather page metadata; called before start()."""
        try:
            self._doc = Poppler.Document.new_from_file(self._uri, None)
        except Exception:
            _logger.exception("cannot open PDF preview document")
            return False
        page = self._doc.get_page(0)
        self._page_w, self._page_h = page.get_size()
        max_dim = max(self._page_w, self._page_h)
        self._base_scale = min(2.0, FIT_WIDTH / max_dim)
        self._page_count = self._doc.get_n_pages()
        return True

    @property
    def page_w(self) -> float:
        return self._page_w

    @property
    def page_h(self) -> float:
        return self._page_h

    @property
    def base_scale(self) -> float:
        return self._base_scale

    @property
    def page_count(self) -> int:
        return self._page_count

    def submit(self, request: _RenderRequest):
        """Queue a render request, replacing any pending one (coalescing)."""
        with self._cond:
            self._pending = request
            self._cond.notify()

    def shutdown(self):
        with self._cond:
            self._stop = True
            self._cond.notify()

    def run(self):
        while True:
            with self._cond:
                while self._pending is None and not self._stop:
                    self._cond.wait()
                if self._stop and self._pending is None:
                    return
                request = self._pending
                self._pending = None
            if request is None:
                continue
            surface = self._render_page(request.page_index, request.zoom)
            if surface is not None:
                self._deliver(surface, request.page_index, request.on_ready)

    def _deliver(self, surface, page_index: int, on_ready):
        """Hand the rendered surface to the GUI thread."""
        from gi.repository import GLib

        GLib.idle_add(on_ready, surface, page_index)

    def _render_page(self, page_index: int, zoom: float):
        try:
            page = self._doc.get_page(page_index)
        except Exception:
            _logger.exception("cannot get PDF page %s", page_index)
            return None
        scale = self._base_scale * zoom
        width = max(1, int(self._page_w * scale))
        height = max(1, int(self._page_h * scale))
        surface = cairo.ImageSurface(cairo.Format.ARGB32, width, height)
        ctx = cairo.Context(surface)
        ctx.set_source_rgb(1, 1, 1)
        ctx.paint()
        ctx.scale(scale, scale)
        page.render_for_printing(ctx)
        return surface


class PdfPreview(Gtk.DrawingArea):
    __gsignals__ = {
        "signature-activated": (
            GObject.SignalFlags.RUN_FIRST,
            None,
            (GObject.TYPE_INT,),
        ),
    }

    def __init__(self, pdf_path: str):
        super().__init__()
        self.pdf_path = pdf_path
        self._worker: _RenderWorker | None = None
        self._surface = None
        self._surface_page = -1
        self._page_w = 612.0
        self._page_h = 792.0
        self._base_scale = 1.0
        self._zoom = 1.0
        self._page_index = 0
        self._page_count = 0
        self._sigs: list[dict] = []
        self._highlight = -1
        self._loading = True
        self._closed = False

        self.set_draw_func(self._draw)
        self.set_hexpand(True)
        self.set_vexpand(True)
        self.set_focusable(True)

        click = Gtk.GestureClick()
        click.connect("pressed", self._on_pressed)
        self.add_controller(click)

        self._load_document()

    # --- loading ---

    def _load_document(self):
        uri = "file://" + os.path.abspath(self.pdf_path)
        self._worker = _RenderWorker(uri)
        if not self._worker.start_document():
            self._worker = None
            self._loading = False
            self.queue_draw()
            return
        self._page_w = self._worker.page_w
        self._page_h = self._worker.page_h
        self._base_scale = self._worker.base_scale
        self._page_count = self._worker.page_count
        self._worker.start()
        self._request_render()
        self.queue_draw()

    def _request_render(self):
        if self._worker is None:
            return
        self._worker.submit(
            _RenderRequest(self._page_index, self._zoom, self._on_surface_ready)
        )

    def _on_surface_ready(self, surface, page_index: int):
        if self._closed:
            return
        self._surface = surface
        self._surface_page = page_index
        self._loading = False
        scale = self._base_scale * self._zoom
        self.set_size_request(
            max(1, int(self._page_w * scale)), max(1, int(self._page_h * scale))
        )
        self.queue_draw()

    def close(self):
        """Stop the render worker thread and release resources."""
        self._closed = True
        if self._worker is not None:
            self._worker.shutdown()

    # --- signature data ---

    def set_signatures(self, signatures: list[dict]):
        """Set the signature list. Each item: ``page``, ``box``, ``label``."""
        cleaned = []
        for sig in signatures:
            box = sig.get("box")
            page = sig.get("page")
            if not box or len(box) != 4 or page is None:
                continue
            cleaned.append(
                {
                    "page": int(page),
                    "box": (float(box[0]), float(box[1]), float(box[2]), float(box[3])),
                    "label": str(sig.get("label", "") or _("PAdES signature")),
                }
            )
        self._sigs = cleaned
        self._highlight = -1
        self.queue_draw()

    @property
    def page_count(self) -> int:
        return self._page_count

    @property
    def current_page(self) -> int:
        return self._page_index

    def set_highlight(self, index: int):
        self._highlight = index if 0 <= index < len(self._sigs) else -1
        self.queue_draw()

    def goto_signature(self, index: int):
        if 0 <= index < len(self._sigs):
            self.goto_page(self._sigs[index]["page"])
            self.set_highlight(index)

    # --- navigation ---

    def goto_page(self, index: int):
        if self._worker is None:
            return
        index = max(0, min(index, self._page_count - 1))
        if index == self._page_index:
            return
        self._page_index = index
        self._loading = True
        self._request_render()
        self.queue_draw()

    def next_page(self):
        self.goto_page(self._page_index + 1)

    def prev_page(self):
        self.goto_page(self._page_index - 1)

    def zoom_in(self):
        self.set_zoom(self._zoom * 1.25)

    def zoom_out(self):
        self.set_zoom(self._zoom / 1.25)

    def set_zoom(self, zoom: float):
        self._zoom = max(MIN_ZOOM, min(MAX_ZOOM, zoom))
        self._loading = True
        self._request_render()
        self.queue_draw()

    # --- coordinates ---

    def _to_pixels(self, box):
        x0, y0, x1, y1 = box
        scale = self._base_scale * self._zoom
        return (
            x0 * scale,
            (self._page_h - y1) * scale,
            x1 * scale,
            (self._page_h - y0) * scale,
        )

    # --- drawing ---

    def _draw(self, _widget, cr, w, h):
        if self._surface is not None and self._surface_page == self._page_index:
            cr.set_source_surface(self._surface, 0, 0)
            cr.paint()
        elif self._loading:
            cr.set_source_rgb(0.93, 0.93, 0.93)
            cr.paint()
            cr.set_source_rgb(0.3, 0.3, 0.3)
            cr.select_font_face("Sans", cairo.FONT_SLANT_NORMAL, cairo.FONT_WEIGHT_NORMAL)
            cr.set_font_size(14)
            ext = cr.text_extents(_("Rendering…"))
            cr.move_to((w - ext.width) / 2 - ext.x_bearing, (h - ext.height) / 2 - ext.y_bearing)
            cr.show_text(_("Rendering…"))

        for idx, sig in enumerate(self._sigs):
            if sig["page"] != self._page_index:
                continue
            sx0, sy0, sx1, sy1 = self._to_pixels(sig["box"])
            width = sx1 - sx0
            height = sy1 - sy0
            selected = idx == self._highlight

            if selected:
                cr.set_source_rgba(0.98, 0.82, 0.1, 0.45)
            else:
                cr.set_source_rgba(0.98, 0.82, 0.1, 0.28)
            cr.rectangle(sx0, sy0, width, height)
            cr.fill()

            if selected:
                cr.set_source_rgba(0.85, 0.6, 0.0, 1.0)
                cr.set_line_width(3)
            else:
                cr.set_source_rgba(0.7, 0.5, 0.0, 1.0)
                cr.set_line_width(1.5)
            cr.rectangle(sx0, sy0, width, height)
            cr.stroke()

    # --- interaction ---

    def _on_pressed(self, _gesture, _n_press, x, y):
        for idx, sig in enumerate(self._sigs):
            if sig["page"] != self._page_index:
                continue
            sx0, sy0, sx1, sy1 = self._to_pixels(sig["box"])
            if (
                sx0 - HIT_TOLERANCE <= x <= sx1 + HIT_TOLERANCE
                and sy0 - HIT_TOLERANCE <= y <= sy1 + HIT_TOLERANCE
            ):
                self.set_highlight(idx)
                self.emit("signature-activated", idx)
                break
