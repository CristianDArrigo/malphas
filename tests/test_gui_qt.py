"""
Smoke tests for the PySide6 GUI (v0.11.x).

Qt's main loop is interactive and requires a display server. CI
runs headless via QT_QPA_PLATFORM=offscreen. We cover:

  - module import (catches syntax / import errors)
  - QSS theme builds without f-string mishaps
  - sigil loader returns a valid pixmap
  - halo compositing produces a larger pixmap
  - BubbleRow constructs in all three side modes
  - MalphasQtWindow construction with node=None (preview path)
  - sidebar row add + key retrieval round-trip
  - send button drop-shadow effect attached

Wire-level behavior (sending messages, draining the AsyncBridge
queue, file transfer) is not asserted here — that's covered by
the existing node tests, which the Qt window only delegates to.

Tests are skipped entirely if PySide6 isn't installed (the
`gui-qt` extra is optional).
"""

from __future__ import annotations

import os

import pytest

# Skip the whole module if PySide6 isn't available — gui-qt is opt-in.
pytest.importorskip("PySide6", reason="gui-qt extra not installed")

# Force offscreen Qt platform so tests work in headless CI.
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6 import QtCore, QtGui, QtWidgets  # noqa: E402

from malphas import gui_qt  # noqa: E402
from malphas import gui_theme as T  # noqa: E402

# ── Fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def qapp():
    app = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])
    yield app
    # Don't quit — pytest reuses the app across tests.


# ── Pure helpers (no Qt) ─────────────────────────────────────────────────────


def test_short_truncates_with_ellipsis():
    assert gui_qt._short("abcdefghijkl", 8) == "abcdefgh…"
    assert gui_qt._short("abc", 8) == "abc"


def test_ts_returns_hhmm():
    s = gui_qt._ts()
    assert len(s) == 5 and s[2] == ":"


def test_avatar_color_is_deterministic():
    a = gui_qt._avatar_color("peer-x")
    b = gui_qt._avatar_color("peer-x")
    c = gui_qt._avatar_color("peer-y")
    assert a == b
    assert a in gui_qt.AVATAR_PALETTE
    # different inputs may collide on the palette (only 10 colors),
    # but we at least assert determinism.
    assert c in gui_qt.AVATAR_PALETTE


def test_avatar_initial_picks_first_letter():
    assert gui_qt._avatar_initial("alice") == "A"
    assert gui_qt._avatar_initial("  bob") == "B"
    assert gui_qt._avatar_initial("") == "?"


# ── QSS / sigil ──────────────────────────────────────────────────────────────


def test_qss_builds_with_palette_tokens():
    qss = gui_qt._qss()
    # All palette tokens used in the sheet should resolve to hex.
    assert T.BG_BASE in qss
    assert T.ACCENT in qss
    # No leftover f-string braces.
    assert "{T." not in qss
    # Per-section anchors present.
    for sel in ["QFrame#Header", "QLabel#BubbleThem", "QLabel#BubbleYou",
                 "QPushButton#AccentButton", "QFrame#PeerRow"]:
        assert sel in qss


def test_sigil_loads_as_pixmap(qapp):
    pm = gui_qt._load_sigil()
    # The wheel ships the asset; if missing the test fails loud.
    assert pm is not None, "src/malphas/assets/sigil.png missing"
    assert isinstance(pm, QtGui.QPixmap)
    assert pm.width() > 0 and pm.height() > 0


def test_sigil_with_halo_pads(qapp):
    pm = gui_qt._load_sigil()
    assert pm is not None
    halo = gui_qt._sigil_with_halo(pm, 100, pad=20)
    assert halo.width() == 140 and halo.height() == 140


# ── Widgets ──────────────────────────────────────────────────────────────────


def test_avatar_widget_constructs(qapp):
    av = gui_qt.Avatar("alice", "peer-x", size=40)
    assert av.size().width() == 40
    assert av.size().height() == 40
    # Pixmap should be set (the painter ran).
    assert not av.pixmap().isNull()


@pytest.mark.parametrize("side", ["you", "them", "sys"])
def test_bubble_row_constructs_in_all_sides(qapp, side):
    row = gui_qt.BubbleRow(
        "hello", "10:00",
        side=side,
        sender="alice" if side != "sys" else None,
        avatar_key="peer-x" if side == "them" else None,
    )
    assert row.layout() is not None
    assert row.layout().count() > 0


def test_main_window_constructs_in_preview_mode(qapp):
    w = gui_qt.MalphasQtWindow()
    assert w.windowTitle() == "malphas"
    # No node attached, so peer count starts at 0; status label exists.
    assert hasattr(w, "status_label")
    # Theme applied (non-empty stylesheet).
    assert len(w.styleSheet()) > 100
    w.close()


def test_sidebar_add_and_select_round_trip(qapp):
    w = gui_qt.MalphasQtWindow()
    w.active = "alice"
    w._add_sidebar_row("alice", "Alice", "peer", is_group=False)
    w._add_sidebar_row("g1", "demo", "2 members", is_group=True)
    assert w.peers.count() == 2

    # The conversation key roundtrips via the user-data role.
    items = [w.peers.item(i) for i in range(w.peers.count())]
    keys = [it.data(w._SIDEBAR_KEY_ROLE) for it in items]
    assert "alice" in keys and "g1" in keys

    # Clicking an item routes to _select.
    w._on_peer_clicked(items[0])
    assert w.active == keys[0]
    w.close()


def test_send_button_has_drop_shadow_effect(qapp):
    """The accent CTA carries a single QGraphicsDropShadowEffect.
    Regression guard: if someone removes the shadow we want to know."""
    w = gui_qt.MalphasQtWindow()
    # Find the Send button by object name.
    sends = [b for b in w.findChildren(QtWidgets.QPushButton)
             if b.objectName() == "AccentButton" and b.text() == "Send"]
    assert len(sends) == 1
    eff = sends[0].graphicsEffect()
    assert isinstance(eff, QtWidgets.QGraphicsDropShadowEffect)
    # Some non-trivial blur configured.
    assert eff.blurRadius() >= 8
    w.close()


def test_add_message_appends_to_conversation(qapp):
    w = gui_qt.MalphasQtWindow()
    w.active = "alice"
    w._add_message("alice", "alice", "ciao", is_self=False,
                     sender_label="alice")
    w._add_message("alice", "you", "ehi", is_self=True,
                     sender_label="you")
    assert len(w.conversations["alice"]) == 2
    msg_kinds = [ev[0] for ev in w.conversations["alice"]]
    assert msg_kinds == ["msg", "msg"]
    w.close()


def test_add_system_does_not_count_as_unread_when_active(qapp):
    w = gui_qt.MalphasQtWindow()
    w.active = "alice"
    w._add_system("alice", "delivered")
    # Active conversation: no unread bump.
    assert "alice" not in w.unread
    w.close()


def test_add_message_to_inactive_marks_unread(qapp):
    w = gui_qt.MalphasQtWindow()
    w.active = "alice"
    w._add_message("bob", "bob", "psst", is_self=False, sender_label="bob")
    assert "bob" in w.unread
    w.close()
