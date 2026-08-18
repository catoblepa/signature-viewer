# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Davide Truffa <davide@catoblepa.org>

"""In-app PDF preview with clickable highlighted signature rectangles.

Renders the PDF pages via Poppler into a ``Gtk.DrawingArea`` and overlays the
signature rectangles (from pyhanko ``sig_field.box`` or pypdf ``/Rect``). The
rectangles are clickable and emit the ``signature-activated`` signal.
"""
from __future__ import annotations

import logging
import os

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
        self._doc = None
        self._surface = None
        self._page_w = 612.0
        self._page_h = 792.0
        self._base_scale = 1.0
        self._zoom = 1.0
        self._page_index = 0
        self._sigs: list[dict] = []
        self._highlight = -1

        self._load_document()
        self.set_draw_func(self._draw)
        self.set_hexpand(True)
        self.set_vexpand(True)
        self.set_focusable(True)

        click = Gtk.GestureClick()
        click.connect("pressed", self._on_pressed)
        self.add_controller(click)

    # --- loading ---

    def _load_document(self):
        uri = "file://" + os.path.abspath(self.pdf_path)
        self._doc = Poppler.Document.new_from_file(uri, None)
        self._page_index = 0
        self._render()

    def _render(self):
        if self._doc is None:
            return
        page = self._doc.get_page(self._page_index)
        self._page_w, self._page_h = page.get_size()
        max_dim = max(self._page_w, self._page_h)
        self._base_scale = min(2.0, FIT_WIDTH / max_dim)

        scale = self._base_scale * self._zoom
        width = max(1, int(self._page_w * scale))
        height = max(1, int(self._page_h * scale))
        self._surface = cairo.ImageSurface(cairo.Format.ARGB32, width, height)
        ctx = cairo.Context(self._surface)
        ctx.set_source_rgb(1, 1, 1)
        ctx.paint()
        ctx.scale(scale, scale)
        page.render_for_printing(ctx)
        self.set_size_request(width, height)

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
        return self._doc.get_n_pages() if self._doc else 0

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
        if self._doc is None:
            return
        index = max(0, min(index, self._doc.get_n_pages() - 1))
        if index == self._page_index:
            return
        self._page_index = index
        self._render()
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
        self._render()
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

    def _draw(self, _widget, cr, _w, _h):
        if self._surface is not None:
            cr.set_source_surface(self._surface, 0, 0)
            cr.paint()

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