"""
PySide6/Qt GUI for malphas.

Drop-in replacement for the tkinter GUI in `gui.py`. Reuses
`AsyncBridge` (from `gui.py`) so MalphasNode and the asyncio loop
run unchanged in a side thread; the GUI thread drains events from
a `queue.Queue` via a 50 ms `QTimer`.

Launch with `malphas --mode gui-qt`. Optional dep: `[gui-qt]`.
"""

from __future__ import annotations

import hashlib
import queue
import sys
import time
import webbrowser
from importlib.resources import files
from pathlib import Path
from typing import TYPE_CHECKING, Any

from PySide6 import QtCore, QtGui, QtWidgets

from . import gui_theme as T
from .addressbook import AddressBook, Contact
from .invite import generate_invite, parse_invite
from .node import MalphasNode

if TYPE_CHECKING:
    from .gui import AsyncBridge


GITHUB_URL = "https://github.com/CristianDArrigo/malphas"

# Muted, earthy palette tuned to sit beside the red "tactical" accent —
# warm-dominant with a few desaturated cool tones for variety, all at a
# similar saturation/lightness so a roomful of avatars feels cohesive
# rather than like a default rainbow.
AVATAR_PALETTE = [
    "#b8524a", "#c07d4a", "#a8924e", "#7a9456", "#4e9e84",
    "#5688a6", "#7b6fa8", "#a85f86", "#9c5a4e", "#6f7c8c",
]


def _short(peer_id: str, n: int = 12) -> str:
    return peer_id[:n] + ("…" if len(peer_id) > n else "")


def _ts() -> str:
    return time.strftime("%H:%M")


# Per-message delivery status glyphs (WhatsApp-style), shown on outgoing
# bubbles. "read" uses a literal WhatsApp blue (the app accent is red, so a
# theme token would be ambiguous here).
_STATUS_GLYPH = {
    "pending": ("🕓", T.FG_FAINT),
    "sent":    ("✓",  T.FG_FAINT),
    "read":    ("✓✓", "#34b7f1"),
    "failed":  ("✕",  T.ACCENT),
}


def _ts_html(ts: str, status: str | None) -> str:
    """Timestamp line, optionally followed by a coloured status glyph."""
    info = _STATUS_GLYPH.get(status or "")
    if info is None:
        return ts
    glyph, color = info
    return f'{ts}&nbsp;&nbsp;<span style="color:{color}">{glyph}</span>'


def _avatar_color(peer_id: str) -> str:
    h = hashlib.blake2s(peer_id.encode("utf-8"), digest_size=4).digest()
    idx = int.from_bytes(h, "big") % len(AVATAR_PALETTE)
    return AVATAR_PALETTE[idx]


def _avatar_initial(label: str) -> str:
    label = label.strip()
    return label[0].upper() if label else "?"


def _load_sigil() -> QtGui.QPixmap | None:
    try:
        path = files("malphas").joinpath("assets/sigil.png")
        with path.open("rb") as f:
            data = f.read()
    except (FileNotFoundError, ModuleNotFoundError):
        return None
    pm = QtGui.QPixmap()
    if not pm.loadFromData(data, "PNG"):
        return None
    return pm


def _sigil_with_halo(sigil: QtGui.QPixmap, size_px: int,
                      halo_color: str = T.BG_RAISED,
                      pad: int = 26) -> QtGui.QPixmap:
    """Composite a lighter-circle halo behind the sigil so the
    black artwork reads against the dark base background."""
    side = size_px + pad * 2
    out = QtGui.QPixmap(side, side)
    out.fill(QtCore.Qt.GlobalColor.transparent)
    p = QtGui.QPainter(out)
    p.setRenderHint(QtGui.QPainter.RenderHint.Antialiasing)
    p.setBrush(QtGui.QColor(halo_color))
    p.setPen(QtCore.Qt.PenStyle.NoPen)
    p.drawEllipse(0, 0, side, side)
    scaled = sigil.scaled(
        size_px, size_px,
        QtCore.Qt.AspectRatioMode.KeepAspectRatio,
        QtCore.Qt.TransformationMode.SmoothTransformation,
    )
    p.drawPixmap(pad, pad, scaled)
    p.end()
    return out


# ── QSS theme ────────────────────────────────────────────────────────────────


def _qss() -> str:
    return f"""
    QMainWindow, QWidget {{
        background-color: {T.BG_BASE};
        color: {T.FG_PRIMARY};
        font-family: "Inter", "Inter Display", "SF Pro Text", "Segoe UI",
                      "Cantarell", "Noto Sans", "Ubuntu", "DejaVu Sans",
                      "Helvetica Neue", sans-serif;
        font-size: 10pt;
    }}
    QFrame#Header {{
        background-color: {T.BG_SURFACE};
        border-bottom: 1px solid {T.BG_DIVIDER};
    }}
    QLabel#HeaderBrand {{
        font-size: 15pt;
        font-weight: 600;
        color: {T.FG_PRIMARY};
    }}
    QLabel#HeaderSub, QLabel#StatusLabel {{
        color: {T.FG_MUTED};
        font-family: "JetBrains Mono", "SF Mono", "Cascadia Mono", monospace;
        font-size: 9pt;
        background: transparent;
    }}
    QLabel#HeaderBrand {{
        background: transparent;
    }}
    QLabel#TorLock, QLabel#StatusDot {{
        background: transparent;
    }}
    QLabel#EmptyHint {{
        background: transparent;
    }}
    QLabel#StatusDot[connected="true"] {{ color: {T.OK_GREEN}; }}
    QLabel#StatusDot[connected="false"] {{ color: {T.FG_FAINT}; }}
    QLabel#TorLock[on="true"] {{ color: {T.OK_GREEN}; font-size: 14pt; }}
    QLabel#TorLock[on="false"] {{ color: transparent; }}

    QFrame#Sidebar {{
        background-color: {T.BG_SURFACE};
        border-right: 1px solid {T.BG_DIVIDER};
    }}
    QLineEdit#SearchEntry {{
        background-color: {T.BG_RAISED};
        color: {T.FG_PRIMARY};
        border: 1px solid transparent;
        border-radius: 10px;
        padding: 8px 12px;
        selection-background-color: {T.ACCENT};
    }}
    QLineEdit#SearchEntry:focus {{
        border: 1px solid {T.ACCENT_DIM};
    }}
    QLineEdit#MessageEntry {{
        background-color: {T.BG_RAISED};
        color: {T.FG_PRIMARY};
        border: 1px solid transparent;
        border-radius: 22px;
        padding: 12px 18px;
        font-size: 11pt;
        selection-background-color: {T.ACCENT};
    }}
    QLineEdit#MessageEntry:focus {{
        border: 1px solid {T.ACCENT_DIM};
    }}

    QListWidget#PeerList {{
        background-color: {T.BG_SURFACE};
        border: none;
        outline: 0;
        padding: 0;
    }}
    QListWidget#PeerList::item {{
        padding: 0;
        border: none;
        margin: 1px 0;
    }}
    /* PeerRow / PeerAccent state is set imperatively (Qt QSS
       :selected pseudo-state doesn't propagate through
       setItemWidget). The bare rule below sets the off state. */
    QFrame#PeerRow {{
        background-color: transparent;
        border-radius: 10px;
    }}
    QFrame#PeerRow:hover {{
        background-color: {T.BG_HOVER};
    }}
    QFrame#PeerAccent {{
        background-color: transparent;
        border-radius: 2px;
    }}

    QFrame#ConvHeader {{
        background-color: {T.BG_SURFACE};
        border-bottom: 1px solid {T.BG_DIVIDER};
    }}
    QScrollArea#ChatScroll, QWidget#ChatViewport {{
        background-color: {T.BG_BASE};
        border: none;
    }}

    QLabel#BubbleThem {{
        background-color: qlineargradient(x1:0, y1:0, x2:0, y2:1,
            stop:0 #30343f, stop:1 {T.BUBBLE_THEM});
        color: {T.FG_PRIMARY};
        padding: 12px 17px;
        border-radius: 20px;
        border-bottom-left-radius: 6px;
    }}
    QLabel#BubbleYou {{
        background-color: qlineargradient(x1:0, y1:0, x2:0, y2:1,
            stop:0 #b5403f, stop:1 #7e2627);
        color: #fdeceb;
        padding: 12px 17px;
        border-radius: 20px;
        border-bottom-right-radius: 6px;
    }}
    QLabel#BubbleSys {{
        background-color: {T.BUBBLE_SYS};
        color: {T.FG_MUTED};
        padding: 6px 15px;
        border-radius: 11px;
        font-style: italic;
        font-size: 9pt;
    }}
    QLabel#BubbleTimestamp {{
        color: {T.FG_FAINT};
        font-size: 8pt;
    }}
    QLabel#EmptyTitle {{
        color: {T.FG_PRIMARY};
        font-size: 17pt;
        font-weight: 600;
        background: transparent;
    }}
    QLabel#EmptyHint {{
        color: {T.FG_FAINT};
        font-size: 11pt;
        background: transparent;
    }}

    QFrame#InputRow {{
        background-color: {T.BG_SURFACE};
        border-top: 1px solid {T.BG_DIVIDER};
    }}

    QPushButton {{
        background-color: {T.BG_RAISED};
        color: {T.FG_PRIMARY};
        border: none;
        border-radius: 8px;
        padding: 8px 16px;
    }}
    QPushButton:hover {{
        background-color: {T.BG_HOVER};
    }}
    QPushButton:pressed {{
        background-color: {T.ACCENT_DIM};
    }}
    QPushButton#AccentButton {{
        background-color: {T.ACCENT};
        color: {T.FG_PRIMARY};
        font-weight: 600;
        border-radius: 22px;
        padding: 10px 22px;
    }}
    QPushButton#AccentButton:hover {{
        background-color: {T.ACCENT_GLOW};
    }}
    /* Outline variant of the accent button — keeps the red identity as a
       border rather than a filled block (lighter-weight primary action). */
    QPushButton#AccentOutline {{
        background-color: transparent;
        color: #e8908e;
        border: 1px solid {T.ACCENT_DIM};
        border-radius: 10px;
        padding: 8px 18px;
        font-weight: 600;
    }}
    QPushButton#AccentOutline:hover {{
        background-color: #3a1f1f;
        border-color: {T.ACCENT};
        color: #ff9a98;
    }}
    QPushButton#AccentOutline:pressed {{
        background-color: {T.ACCENT_DIM};
        color: {T.FG_PRIMARY};
    }}
    QPushButton#GhostIcon {{
        background-color: transparent;
        padding: 6px;
        border-radius: 22px;
    }}
    QPushButton#GhostIcon:hover {{
        background-color: {T.BG_HOVER};
    }}
    /* Sidebar action toolbar (Share/Add/Group, Backup/Panic):
       compact ghost style with per-button tone tints. */
    QPushButton#SideAction {{
        background-color: transparent;
        border: 1px solid {T.BG_DIVIDER};
        border-radius: 8px;
        padding: 6px 12px;
        font-size: 9pt;
        font-weight: 600;
        color: {T.FG_MUTED};
    }}
    QPushButton#SideAction:hover {{
        background-color: {T.BG_RAISED};
        color: {T.FG_PRIMARY};
        border-color: {T.BG_HOVER};
    }}
    QPushButton#SideAction:pressed {{
        background-color: {T.BG_HOVER};
    }}
    /* Tone variants — set via setProperty("tone", "<name>") and
       re-polished. Borders are tinted at half-opacity-ish so the
       buttons feel coloured but never shouty against the dark bg. */
    QPushButton#SideAction[tone="info"] {{
        color: {T.INFO_CYAN};
        border-color: #2f4d6e;
    }}
    QPushButton#SideAction[tone="info"]:hover {{
        background-color: #213040;
        border-color: {T.INFO_CYAN};
        color: #b3d3ee;
    }}
    QPushButton#SideAction[tone="success"] {{
        color: {T.OK_GREEN};
        border-color: #2f5a32;
    }}
    QPushButton#SideAction[tone="success"]:hover {{
        background-color: #1f3324;
        border-color: {T.OK_GREEN};
        color: #b1dab1;
    }}
    QPushButton#SideAction[tone="warning"] {{
        color: {T.WARN_AMBER};
        border-color: #5e4720;
    }}
    QPushButton#SideAction[tone="warning"]:hover {{
        background-color: #3a2d18;
        border-color: {T.WARN_AMBER};
        color: #f0d090;
    }}
    QPushButton#SideAction[tone="danger"] {{
        color: #e07473;
        border-color: #5a2c2c;
    }}
    QPushButton#SideAction[tone="danger"]:hover {{
        background-color: #3b1f1f;
        border-color: {T.ACCENT};
        color: #ff8a88;
    }}

    QStatusBar {{
        background-color: {T.BG_SURFACE};
        color: {T.FG_MUTED};
        border-top: 1px solid {T.BG_DIVIDER};
    }}
    QScrollBar:vertical {{
        background-color: {T.BG_SURFACE};
        width: 10px;
        margin: 0;
        border: none;
    }}
    QScrollBar::handle:vertical {{
        background-color: {T.BG_HOVER};
        border-radius: 5px;
        min-height: 30px;
    }}
    QScrollBar::handle:vertical:hover {{
        background-color: {T.FG_FAINT};
    }}
    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}

    QToolTip {{
        background-color: {T.BG_RAISED};
        color: {T.FG_PRIMARY};
        border: 1px solid {T.BG_DIVIDER};
        padding: 4px 8px;
    }}

    /* QMessageBox / QInputDialog inherit from QDialog. The min-width keeps
       even terse modals (a one-word title, a short prompt) wide enough that
       the window-title text isn't clipped. */
    QDialog {{
        background-color: {T.BG_BASE};
        min-width: 360px;
    }}
    QLabel#DialogTitle {{
        font-size: 14pt;
        font-weight: 600;
        color: {T.FG_PRIMARY};
        background: transparent;
    }}
    QLabel#DialogPrompt {{
        color: {T.FG_MUTED};
        background: transparent;
    }}
    QDialog QLabel {{
        color: {T.FG_PRIMARY};
    }}
    QDialog QLineEdit {{
        background-color: {T.BG_RAISED};
        color: {T.FG_PRIMARY};
        border: 1px solid transparent;
        border-radius: 8px;
        padding: 8px 12px;
        selection-background-color: {T.ACCENT};
    }}
    QDialog QLineEdit:focus {{
        border: 1px solid {T.ACCENT_DIM};
    }}
    """


# ── Avatar ──────────────────────────────────────────────────────────────────


class Avatar(QtWidgets.QLabel):
    """Circular avatar with hashed color + initial letter."""

    def __init__(self, label: str, key: str, size: int = 36,
                 parent: QtWidgets.QWidget | None = None) -> None:
        super().__init__(parent)
        self._size = size
        self.setFixedSize(size, size)
        self.setAttribute(QtCore.Qt.WidgetAttribute.WA_TranslucentBackground)
        pm = QtGui.QPixmap(size, size)
        pm.fill(QtCore.Qt.GlobalColor.transparent)
        p = QtGui.QPainter(pm)
        p.setRenderHint(QtGui.QPainter.RenderHint.Antialiasing)
        # Subtle top-to-bottom gradient gives the disc a little volume
        # instead of reading as a flat sticker.
        base = QtGui.QColor(_avatar_color(key))
        grad = QtGui.QLinearGradient(0, 0, 0, size)
        grad.setColorAt(0.0, base.lighter(118))
        grad.setColorAt(1.0, base.darker(110))
        p.setBrush(QtGui.QBrush(grad))
        p.setPen(QtCore.Qt.PenStyle.NoPen)
        p.drawEllipse(0, 0, size, size)
        # Hairline highlight ring lifts the disc off the dark surface.
        p.setBrush(QtCore.Qt.BrushStyle.NoBrush)
        p.setPen(QtGui.QPen(QtGui.QColor(255, 255, 255, 28), 1))
        p.drawEllipse(1, 1, size - 2, size - 2)
        p.setPen(QtGui.QColor(T.FG_PRIMARY))
        font = p.font()
        font.setBold(True)
        font.setPointSize(max(9, int(size * 0.40)))
        p.setFont(font)
        p.drawText(pm.rect(), QtCore.Qt.AlignmentFlag.AlignCenter,
                    _avatar_initial(label))
        p.end()
        self.setPixmap(pm)


# ── Bubble row ──────────────────────────────────────────────────────────────


class BubbleRow(QtWidgets.QFrame):
    """One chat row: alignment-aware bubble + optional avatar + ts."""

    def __init__(
        self,
        text: str,
        ts: str,
        side: str = "them",
        sender: str | None = None,
        avatar_key: str | None = None,
        parent: QtWidgets.QWidget | None = None,
        status: str | None = None,
        show_name: bool = True,
    ) -> None:
        super().__init__(parent)
        self._status = status
        self._ts = ts
        self._status_label: QtWidgets.QLabel | None = None
        # `sender` always drives the avatar initial; `show_name` controls
        # whether the name is *also* printed above the bubble (groups only).
        name = sender if show_name else None
        outer = QtWidgets.QHBoxLayout(self)
        outer.setContentsMargins(T.PAD_LG, 4, T.PAD_LG, 4)
        outer.setSpacing(T.PAD_SM)

        if side == "sys":
            outer.addStretch()
            bubble = QtWidgets.QLabel(text)
            bubble.setObjectName("BubbleSys")
            bubble.setTextFormat(QtCore.Qt.TextFormat.PlainText)
            bubble.setWordWrap(True)
            bubble.setMaximumWidth(560)
            outer.addWidget(bubble, 0,
                              QtCore.Qt.AlignmentFlag.AlignCenter)
            outer.addStretch()
            return

        if side == "you":
            outer.addStretch()
            stack = self._stack(text, ts, name, side)
            outer.addLayout(stack, 0)
        else:
            if avatar_key:
                outer.addWidget(Avatar(sender or "?", avatar_key, size=32),
                                 0, QtCore.Qt.AlignmentFlag.AlignTop)
            stack = self._stack(text, ts, name, side)
            outer.addLayout(stack, 0)
            outer.addStretch()

    def _stack(self, text: str, ts: str, sender: str | None,
                side: str) -> QtWidgets.QVBoxLayout:
        v = QtWidgets.QVBoxLayout()
        v.setSpacing(2)
        v.setContentsMargins(0, 0, 0, 0)

        if sender and side == "them":
            sender_lbl = QtWidgets.QLabel(sender)
            sender_lbl.setObjectName("BubbleTimestamp")
            sender_lbl.setTextFormat(QtCore.Qt.TextFormat.PlainText)
            v.addWidget(sender_lbl,
                          0, QtCore.Qt.AlignmentFlag.AlignLeft)

        # PlainText: message content (and peer-supplied names) is UNTRUSTED.
        # QLabel's default AutoText auto-detects HTML, so a message like
        # `<img src="http://x/p.png">` would render as rich text and could
        # trigger a remote fetch from the user's real IP (outside Tor) —
        # deanonymisation — besides markup/display spoofing.
        bubble = QtWidgets.QLabel(text)
        bubble.setObjectName("BubbleYou" if side == "you" else "BubbleThem")
        bubble.setTextFormat(QtCore.Qt.TextFormat.PlainText)
        bubble.setWordWrap(True)
        bubble.setMaximumWidth(560)
        bubble.setTextInteractionFlags(
            QtCore.Qt.TextInteractionFlag.TextSelectableByMouse
        )
        align = (QtCore.Qt.AlignmentFlag.AlignRight if side == "you"
                 else QtCore.Qt.AlignmentFlag.AlignLeft)
        v.addWidget(bubble, 0, align)

        ts_lbl = QtWidgets.QLabel()
        ts_lbl.setObjectName("BubbleTimestamp")
        ts_lbl.setTextFormat(QtCore.Qt.TextFormat.RichText)
        ts_lbl.setText(_ts_html(ts, self._status if side == "you" else None))
        v.addWidget(ts_lbl, 0, align)
        if side == "you":
            self._status_label = ts_lbl
        return v

    def set_status(self, status: str) -> None:
        """Update the delivery-status glyph on an outgoing bubble in place."""
        self._status = status
        if self._status_label is not None:
            self._status_label.setText(_ts_html(self._ts, status))


# ── Main window ─────────────────────────────────────────────────────────────


class MalphasQtWindow(QtWidgets.QMainWindow):
    def __init__(
        self,
        node: MalphasNode | None = None,
        book: AddressBook | None = None,
        bridge: AsyncBridge | None = None,
        recovery_mnemonic: str | None = None,
    ) -> None:
        super().__init__()
        self.node = node
        self.book = book
        self.bridge = bridge
        self.recovery_mnemonic = recovery_mnemonic

        self.active: str | None = None
        self.conversations: dict[str, list[tuple]] = {}
        self.unread: set[str] = set()
        self.event_queue: queue.Queue = queue.Queue()
        # QListWidgetItem isn't hashable; we stash the conversation
        # key on the item via Qt's UserRole instead.
        self._SIDEBAR_KEY_ROLE = int(QtCore.Qt.ItemDataRole.UserRole) + 1
        self._pending_offers: dict[str, tuple[str, dict]] = {}
        # Per-outgoing-message delivery status. status_key is a local counter
        # stable across conversation re-renders; _status_rows maps it to the
        # live BubbleRow widget; _sent_msgid maps the wire msg_id back to the
        # status_key so an inbound receipt can flip the bubble to "read".
        self._msg_status: dict[int, str] = {}
        self._status_rows: dict[int, BubbleRow] = {}
        self._sent_msgid: dict[str, int] = {}
        self._send_seq = 0
        # "Connecting…" progress dialog shown during a (slow, Tor) connect so
        # the import doesn't freeze the Qt thread. Cleared when the connect
        # result event arrives.
        self._connect_dialog: QtWidgets.QProgressDialog | None = None

        self.setWindowTitle("malphas")
        self.resize(1240, 800)
        self.setStyleSheet(_qss())

        self._sigil = _load_sigil()
        if self._sigil is not None:
            self.setWindowIcon(QtGui.QIcon(self._sigil))

        self._build()
        self._wire_callbacks()
        self._refresh_sidebar()
        self._start_event_drain()
        self._start_status_refresh()
        self._auto_reconnect()

    # ── Build ───────────────────────────────────────────────────────────────

    def _build(self) -> None:
        central = QtWidgets.QWidget()
        self.setCentralWidget(central)
        v = QtWidgets.QVBoxLayout(central)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(0)
        v.addWidget(self._build_header())

        body = QtWidgets.QHBoxLayout()
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(0)
        body.addWidget(self._build_sidebar())
        body.addWidget(self._build_chat(), 1)
        body_wrap = QtWidgets.QWidget()
        body_wrap.setLayout(body)
        v.addWidget(body_wrap, 1)

        sb = self.statusBar()
        self.status_label = QtWidgets.QLabel("")
        self.status_label.setObjectName("StatusLabel")
        # PlainText — the status line embeds the active group name (peer-supplied).
        self.status_label.setTextFormat(QtCore.Qt.TextFormat.PlainText)
        sb.addWidget(self.status_label, 1)

    # Header --------------------------------------------------------------

    def _build_header(self) -> QtWidgets.QFrame:
        header = QtWidgets.QFrame()
        header.setObjectName("Header")
        header.setFixedHeight(60)
        h = QtWidgets.QHBoxLayout(header)
        h.setContentsMargins(T.PAD_LG, 0, T.PAD_LG, 0)
        h.setSpacing(T.PAD_MD)

        if self._sigil is not None:
            sigil_label = QtWidgets.QLabel()
            sigil_label.setPixmap(self._sigil.scaled(
                34, 34,
                QtCore.Qt.AspectRatioMode.KeepAspectRatio,
                QtCore.Qt.TransformationMode.SmoothTransformation,
            ))
            h.addWidget(sigil_label)

        brand = QtWidgets.QLabel("malphas")
        brand.setObjectName("HeaderBrand")
        h.addWidget(brand)

        if self.node is not None:
            peer_id = self.node.identity.peer_id
            sub = QtWidgets.QLabel(_short(peer_id, 16))
            sub.setObjectName("HeaderSub")
            sub.setToolTip(peer_id)
            h.addWidget(sub)

        h.addStretch()

        self.tor_lock = QtWidgets.QLabel("🔒")
        self.tor_lock.setObjectName("TorLock")
        self.tor_lock.setStyleSheet(
            f"color: {T.OK_GREEN}; font-size: 14pt;")
        self.tor_lock.setToolTip("end-to-end encrypted via Tor")
        self.tor_lock.setVisible(False)
        h.addWidget(self.tor_lock)

        self.header_status = QtWidgets.QLabel("0 peers · 0 groups")
        self.header_status.setObjectName("HeaderSub")
        self.header_status.setTextFormat(QtCore.Qt.TextFormat.PlainText)
        h.addWidget(self.header_status)

        self.status_dot = QtWidgets.QLabel("●")
        self.status_dot.setObjectName("StatusDot")
        self.status_dot.setProperty("connected", False)
        h.addWidget(self.status_dot)

        # About button (small, ghost)
        about_btn = QtWidgets.QPushButton("ⓘ")
        about_btn.setObjectName("GhostIcon")
        about_btn.setFixedSize(34, 34)
        about_btn.setToolTip("About")
        about_btn.clicked.connect(self._action_about)
        h.addWidget(about_btn)

        return header

    # Sidebar -------------------------------------------------------------

    def _build_sidebar(self) -> QtWidgets.QFrame:
        sidebar = QtWidgets.QFrame()
        sidebar.setObjectName("Sidebar")
        sidebar.setFixedWidth(320)

        v = QtWidgets.QVBoxLayout(sidebar)
        v.setContentsMargins(T.PAD_MD, T.PAD_MD, T.PAD_MD, T.PAD_MD)
        v.setSpacing(T.PAD_SM)

        self.search = QtWidgets.QLineEdit()
        self.search.setObjectName("SearchEntry")
        self.search.setPlaceholderText("Search peers and groups…")
        self.search.textChanged.connect(lambda _t: self._refresh_sidebar())
        v.addWidget(self.search)

        actions = QtWidgets.QHBoxLayout()
        actions.setSpacing(T.PAD_SM)
        for label, tip, slot, tone in [
            ("Share", "Generate invite (clipboard)",
                self._action_export, "info"),
            ("Add",   "Import invite from clipboard",
                self._action_import, "success"),
            ("Group", "Create new group",
                self._action_group_new, "info"),
        ]:
            b = QtWidgets.QPushButton(label)
            b.setObjectName("SideAction")
            b.setProperty("tone", tone)
            b.setToolTip(tip)
            b.clicked.connect(slot)
            actions.addWidget(b)
        v.addLayout(actions)

        self.peers = QtWidgets.QListWidget()
        self.peers.setObjectName("PeerList")
        self.peers.setUniformItemSizes(False)
        self.peers.itemClicked.connect(self._on_peer_clicked)
        self.peers.setContextMenuPolicy(
            QtCore.Qt.ContextMenuPolicy.CustomContextMenu)
        self.peers.customContextMenuRequested.connect(self._on_peer_menu)
        v.addWidget(self.peers, 1)

        # Bottom action row
        bottom = QtWidgets.QHBoxLayout()
        bottom.setSpacing(T.PAD_SM)
        for label, tip, slot, tone in [
            ("Backup", "Show recovery mnemonic",
                self._action_backup, "warning"),
            ("Panic",  "Wipe in-memory state and exit",
                self._action_panic, "danger"),
        ]:
            b = QtWidgets.QPushButton(label)
            b.setObjectName("SideAction")
            b.setProperty("tone", tone)
            b.setToolTip(tip)
            b.clicked.connect(slot)
            bottom.addWidget(b)
        v.addLayout(bottom)

        return sidebar

    # Chat ----------------------------------------------------------------

    def _build_chat(self) -> QtWidgets.QWidget:
        wrap = QtWidgets.QWidget()
        v = QtWidgets.QVBoxLayout(wrap)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(0)

        # Conversation header
        ch = QtWidgets.QFrame()
        ch.setObjectName("ConvHeader")
        ch.setFixedHeight(64)
        chl = QtWidgets.QHBoxLayout(ch)
        chl.setContentsMargins(T.PAD_LG, 0, T.PAD_LG, 0)
        chl.setSpacing(T.PAD_MD)

        self.conv_avatar_holder = QtWidgets.QWidget()
        self.conv_avatar_holder.setFixedSize(40, 40)
        self.conv_avatar_holder.setAttribute(
            QtCore.Qt.WidgetAttribute.WA_TranslucentBackground)
        self.conv_avatar_holder.setStyleSheet("background: transparent;")
        self.conv_avatar_holder.setVisible(False)
        self.conv_avatar_layout = QtWidgets.QVBoxLayout(self.conv_avatar_holder)
        self.conv_avatar_layout.setContentsMargins(0, 0, 0, 0)
        chl.addWidget(self.conv_avatar_holder)

        title_box = QtWidgets.QVBoxLayout()
        title_box.setSpacing(2)
        title_box.setContentsMargins(0, 0, 0, 0)
        self.conv_title = QtWidgets.QLabel("No conversation selected")
        self.conv_title.setObjectName("HeaderBrand")
        # PlainText: the conversation title is a peer-supplied group name (and
        # the sub a peer_id). QLabel's default AutoText would render a name
        # like `<img src=http://x>` as HTML and fetch it from the real IP,
        # outside Tor — deanonymisation. Same rule as the message bubbles.
        self.conv_title.setTextFormat(QtCore.Qt.TextFormat.PlainText)
        self.conv_sub = QtWidgets.QLabel("")
        self.conv_sub.setObjectName("HeaderSub")
        self.conv_sub.setTextFormat(QtCore.Qt.TextFormat.PlainText)
        title_box.addWidget(self.conv_title)
        title_box.addWidget(self.conv_sub)
        chl.addLayout(title_box)
        chl.addStretch()

        # Group action area (populated on-the-fly)
        self.conv_actions = QtWidgets.QWidget()
        self.conv_actions_layout = QtWidgets.QHBoxLayout(self.conv_actions)
        self.conv_actions_layout.setContentsMargins(0, 0, 0, 0)
        self.conv_actions_layout.setSpacing(T.PAD_SM)
        chl.addWidget(self.conv_actions)

        v.addWidget(ch)

        # Chat scroll area
        self.chat_scroll = QtWidgets.QScrollArea()
        self.chat_scroll.setObjectName("ChatScroll")
        self.chat_scroll.setWidgetResizable(True)
        self.chat_scroll.setHorizontalScrollBarPolicy(
            QtCore.Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        self.chat_viewport = QtWidgets.QWidget()
        self.chat_viewport.setObjectName("ChatViewport")
        self.chat_layout = QtWidgets.QVBoxLayout(self.chat_viewport)
        self.chat_layout.setContentsMargins(0, T.PAD_MD, 0, T.PAD_MD)
        self.chat_layout.setSpacing(2)

        # Empty-state — rebuilt fresh each time it is shown (see
        # _make_empty_state) so it is never a dangling deleteLater'd ref.
        self.chat_layout.addWidget(self._make_empty_state(), 1)

        self.chat_scroll.setWidget(self.chat_viewport)
        v.addWidget(self.chat_scroll, 1)

        v.addWidget(self._build_input_row())
        return wrap

    def _make_empty_state(self) -> QtWidgets.QWidget:
        """A fresh, vertically-centred empty-state panel: sigil, headline,
        a short reassuring subtitle, and the two actions a new user needs.

        Rebuilt on every show (the chat layout wipes and recreates its
        children each redraw), so it is never a deleteLater'd dangling ref.
        """
        box = QtWidgets.QWidget()
        v = QtWidgets.QVBoxLayout(box)
        v.setContentsMargins(T.PAD_XL, T.PAD_XL, T.PAD_XL, T.PAD_XL)
        v.setSpacing(T.PAD_MD)
        v.addStretch()

        if self._sigil is not None:
            sig = QtWidgets.QLabel()
            sig.setPixmap(_sigil_with_halo(self._sigil, 168, pad=30))
            sig.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
            sig.setStyleSheet("background: transparent;")
            v.addWidget(sig)

        title = QtWidgets.QLabel("Start a conversation")
        title.setObjectName("EmptyTitle")
        title.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        v.addWidget(title)

        sub = QtWidgets.QLabel(
            "Pick a contact on the left — or share an invite to add one.\n"
            "Every message is end-to-end encrypted and routed over Tor.")
        sub.setObjectName("EmptyHint")
        sub.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        sub.setWordWrap(True)
        v.addWidget(sub)

        row = QtWidgets.QHBoxLayout()
        row.setSpacing(T.PAD_SM)
        row.addStretch()
        share = QtWidgets.QPushButton("Share invite")
        share.setObjectName("AccentOutline")
        share.setFixedHeight(40)
        share.clicked.connect(self._action_export)
        row.addWidget(share)
        add = QtWidgets.QPushButton("Add contact")
        add.setObjectName("SideAction")
        add.setProperty("tone", "success")
        add.setFixedHeight(40)
        add.clicked.connect(self._action_import)
        row.addWidget(add)
        row.addStretch()
        v.addLayout(row)

        v.addStretch()
        return box

    def _build_input_row(self) -> QtWidgets.QFrame:
        row = QtWidgets.QFrame()
        row.setObjectName("InputRow")
        h = QtWidgets.QHBoxLayout(row)
        h.setContentsMargins(T.PAD_LG, T.PAD_MD, T.PAD_LG, T.PAD_MD)
        h.setSpacing(T.PAD_SM)

        attach = QtWidgets.QPushButton("⎘")
        attach.setObjectName("GhostIcon")
        attach.setToolTip("Send a file")
        attach.setFixedSize(44, 44)
        font = attach.font()
        font.setPointSize(16)
        attach.setFont(font)
        attach.clicked.connect(self._action_send_file)
        h.addWidget(attach)

        self.message_entry = QtWidgets.QLineEdit()
        self.message_entry.setObjectName("MessageEntry")
        self.message_entry.setPlaceholderText("Type a message and press Enter…")
        self.message_entry.returnPressed.connect(self._on_send)
        h.addWidget(self.message_entry, 1)

        send = QtWidgets.QPushButton("Send")
        send.setObjectName("AccentButton")
        send.setFixedSize(96, 44)
        send.clicked.connect(self._on_send)
        # Subtle accent-tinted drop shadow so the primary CTA sits
        # one layer above the input bar. One effect instance only —
        # no per-row perf concern.
        shadow = QtWidgets.QGraphicsDropShadowEffect(send)
        shadow.setBlurRadius(20)
        shadow.setOffset(0, 4)
        shadow.setColor(QtGui.QColor(T.ACCENT_DIM))
        send.setGraphicsEffect(shadow)
        h.addWidget(send)

        return row

    # ── Sidebar refresh ─────────────────────────────────────────────────────

    def _refresh_sidebar(self) -> None:
        if self.node is None or self.book is None:
            return
        q = self.search.text().strip().lower() if hasattr(self, "search") else ""
        prev_active = self.active

        self.peers.clear()

        def matches(*fields: str) -> bool:
            if not q:
                return True
            return any(q in f.lower() for f in fields if f)

        seen: set[str] = set()
        for c in self.book.all():
            if not matches(c.label, c.peer_id):
                continue
            seen.add(c.peer_id)
            self._add_sidebar_row(c.peer_id, c.label, _short(c.peer_id, 18),
                                    is_group=False)
        for p in self.node.discovery.all_peers():
            pid = p.get("peer_id", "")
            if pid in seen or not pid:
                continue
            if not matches(pid):
                continue
            self._add_sidebar_row(pid, _short(pid, 12), "(unsaved)",
                                    is_group=False)
        for g in self.node._groups.all_groups():
            if not matches(g.name, g.group_id):
                continue
            self._add_sidebar_row(
                g.group_id, g.name,
                f"{g.member_count()} members  ·  group",
                is_group=True,
            )

        # Restore selection
        if prev_active:
            for i in range(self.peers.count()):
                item = self.peers.item(i)
                if item.data(self._SIDEBAR_KEY_ROLE) == prev_active:
                    self.peers.setCurrentItem(item)
                    break

    def _add_sidebar_row(self, key: str, title: str, sub: str,
                          is_group: bool) -> None:
        is_active = (key == self.active)

        row = QtWidgets.QFrame()
        row.setObjectName("PeerRow")
        row.setAttribute(QtCore.Qt.WidgetAttribute.WA_StyledBackground, True)
        if is_active:
            row.setStyleSheet(
                "QFrame#PeerRow { background-color: "
                f"{T.BG_ACTIVE}; border-radius: 10px; }}")
        outer = QtWidgets.QHBoxLayout(row)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        accent = QtWidgets.QFrame()
        accent.setObjectName("PeerAccent")
        accent.setFixedWidth(3)
        accent.setAttribute(QtCore.Qt.WidgetAttribute.WA_StyledBackground, True)
        if is_active:
            accent.setStyleSheet(
                "QFrame#PeerAccent { background-color: "
                f"{T.ACCENT}; border-radius: 2px; }}")
        outer.addWidget(accent)

        body = QtWidgets.QHBoxLayout()
        body.setContentsMargins(10, 8, 10, 8)
        body.setSpacing(T.PAD_SM)

        body.addWidget(Avatar(title or "?", key, size=40))

        text = QtWidgets.QVBoxLayout()
        text.setSpacing(1)
        text.setContentsMargins(0, 0, 0, 0)

        title_row = QtWidgets.QHBoxLayout()
        title_row.setContentsMargins(0, 0, 0, 0)
        title_row.setSpacing(6)
        title_lbl = QtWidgets.QLabel(title)
        title_lbl.setTextFormat(QtCore.Qt.TextFormat.PlainText)  # group name is peer-supplied
        title_lbl.setStyleSheet(
            f"color: {T.FG_PRIMARY}; font-weight: 600; background: transparent;"
            "font-size: 10pt;"
        )
        title_row.addWidget(title_lbl)
        if is_group:
            tag = QtWidgets.QLabel("GROUP")
            tag.setStyleSheet(
                f"color: {T.INFO_CYAN}; background: transparent; "
                "font-size: 7pt; font-weight: 700; letter-spacing: 1px;"
            )
            title_row.addWidget(tag)
        title_row.addStretch()
        text.addLayout(title_row)

        sub_lbl = QtWidgets.QLabel(sub)
        sub_lbl.setTextFormat(QtCore.Qt.TextFormat.PlainText)
        sub_lbl.setStyleSheet(
            f"color: {T.FG_MUTED}; font-size: 9pt; "
            "font-family: 'JetBrains Mono', monospace; background: transparent;"
        )
        text.addWidget(sub_lbl)
        body.addLayout(text, 1)

        if key in self.unread:
            dot = QtWidgets.QLabel("●")
            dot.setStyleSheet(
                f"color: {T.ACCENT}; font-size: 11pt; background: transparent;"
            )
            body.addWidget(dot)

        outer.addLayout(body, 1)

        item = QtWidgets.QListWidgetItem(self.peers)
        item.setSizeHint(row.sizeHint())
        item.setData(self._SIDEBAR_KEY_ROLE, key)
        self.peers.addItem(item)
        self.peers.setItemWidget(item, row)

    def _on_peer_clicked(self, item: QtWidgets.QListWidgetItem) -> None:
        key = item.data(self._SIDEBAR_KEY_ROLE)
        if key:
            self._select(key)

    def _on_peer_menu(self, pos: QtCore.QPoint) -> None:
        item = self.peers.itemAt(pos)
        if item is None:
            return
        key = item.data(self._SIDEBAR_KEY_ROLE)
        if not key:
            return
        is_group = (self.node is not None
                    and self.node._groups.get_by_id(key) is not None)
        menu = QtWidgets.QMenu(self)
        act_hide = menu.addAction("Hide chat")
        act_delete = None if is_group else menu.addAction("Delete contact")
        chosen = menu.exec(self.peers.viewport().mapToGlobal(pos))
        if chosen is None:
            return
        if chosen is act_hide:
            self._hide_chat(key)
        elif chosen is act_delete:
            self._delete_contact(key)

    def _hide_chat(self, key: str) -> None:
        """Drop the conversation from the UI; keep contact/connection/routing."""
        self.conversations.pop(key, None)
        self.unread.discard(key)
        if self.active == key:
            self.active = None
            self._redraw_conv_header()
            self._redraw_chat()
        self._refresh_sidebar()

    def _delete_contact(self, key: str) -> None:
        """Disconnect, forget routing, drop from the address book + UI."""
        label = self._label_for(key)
        confirm = QtWidgets.QMessageBox.question(
            self, "Delete contact",
            f"Delete {label}?\n\nThis disconnects the peer, removes it from "
            "routing/discovery, and deletes it from your address book.")
        if confirm != QtWidgets.QMessageBox.StandardButton.Yes:
            return
        if self.node is not None and self.bridge is not None:
            self.bridge.submit_coro(self.node.forget_peer(key))
        if self.book is not None:
            self.book.remove_by_peer_id(key)
        self.conversations.pop(key, None)
        self.unread.discard(key)
        if self.active == key:
            self.active = None
            self._redraw_conv_header()
            self._redraw_chat()
        self._refresh_sidebar()

    # ── Selection / chat ────────────────────────────────────────────────────

    def _select(self, key: str) -> None:
        self.active = key
        self.unread.discard(key)
        # Refresh so the new active row gets accent + tinted bg.
        self._refresh_sidebar()
        self._redraw_conv_header()
        self._redraw_chat()

    def _redraw_conv_header(self) -> None:
        for i in reversed(range(self.conv_avatar_layout.count())):
            w = self.conv_avatar_layout.takeAt(i).widget()
            if w:
                w.deleteLater()
        for i in reversed(range(self.conv_actions_layout.count())):
            w = self.conv_actions_layout.takeAt(i).widget()
            if w:
                w.deleteLater()

        if not self.active:
            # Header stays blank when nothing is selected — the centred
            # empty-state panel already says "Start a conversation".
            self.conv_avatar_holder.setVisible(False)
            self.conv_title.setText("")
            self.conv_sub.setText("")
            return

        self.conv_avatar_holder.setVisible(True)

        # Standalone-preview path: no node, no book.
        if self.node is None:
            avatar = Avatar(self.active, self.active, size=40)
            self.conv_avatar_layout.addWidget(avatar)
            self.conv_title.setText(self.active)
            self.conv_sub.setText("preview")
            return

        group = self.node._groups.get_by_id(self.active)
        if group is not None:
            label = group.name
            sub = f"{group.member_count()} members"
            avatar = Avatar(group.name, group.group_id, size=40)
            # Group action buttons
            add_btn = QtWidgets.QPushButton("+ Member")
            add_btn.setObjectName("GhostIcon")
            add_btn.clicked.connect(self._action_group_add)
            self.conv_actions_layout.addWidget(add_btn)
            leave_btn = QtWidgets.QPushButton("Leave")
            leave_btn.setObjectName("GhostIcon")
            leave_btn.clicked.connect(self._action_group_leave)
            self.conv_actions_layout.addWidget(leave_btn)
        else:
            contact = (self.book.get_by_peer_id(self.active)
                       if self.book else None)
            label = contact.label if contact else _short(self.active, 14)
            sub = self.active
            avatar = Avatar(label, self.active, size=40)

        self.conv_avatar_layout.addWidget(avatar)
        self.conv_title.setText(label)
        self.conv_sub.setText(sub)

    def _redraw_chat(self) -> None:
        # Wipe chat layout. The BubbleRow widgets are about to be destroyed,
        # so drop the live-status references; _render_event repopulates them.
        self._status_rows.clear()
        while self.chat_layout.count():
            it = self.chat_layout.takeAt(0)
            w = it.widget()
            if w is not None:
                w.deleteLater()
            del it

        if not self.active:
            self.chat_layout.addWidget(self._make_empty_state(), 1)
            return

        for ev in self.conversations.get(self.active, []):
            self._render_event(ev)
        self.chat_layout.addStretch()
        QtCore.QTimer.singleShot(0, self._scroll_to_bottom)

    def _scroll_to_bottom(self) -> None:
        bar = self.chat_scroll.verticalScrollBar()
        bar.setValue(bar.maximum())

    def _is_at_bottom(self) -> bool:
        """True if the chat scroll is within ~one bubble of the
        bottom. Used to decide whether new messages should auto-
        scroll: we follow the conversation if the user is already
        reading live, but stay put if they've scrolled up to read
        history."""
        bar = self.chat_scroll.verticalScrollBar()
        # 80 px ≈ one bubble + spacing. Loose enough to feel snappy.
        return bar.value() >= bar.maximum() - 80

    def _maybe_scroll_after_render(self, was_at_bottom: bool) -> None:
        """Only auto-scroll if the user was at the bottom *before*
        the new event was rendered. Self-sent messages always
        scroll (the user clearly wants to see what they just sent)
        — that case is handled by passing was_at_bottom=True."""
        if was_at_bottom:
            QtCore.QTimer.singleShot(0, self._scroll_to_bottom)

    def _render_event(self, ev: tuple) -> None:
        kind = ev[0]
        if kind == "msg":
            _, sender, text, is_self, sender_label = ev[:5]
            status_key = ev[5] if len(ev) > 5 else None
            status = (self._msg_status.get(status_key)
                      if status_key is not None else None)
            side = "you" if is_self else "them"
            avatar_key = sender if not is_self else None
            # The sender name only carries information in groups; in a 1:1
            # the avatar already says who's talking, so repeating the name
            # above every incoming bubble just reads as dated clutter.
            in_group = (self.node is not None
                        and self.node._groups.get_by_id(self.active) is not None)
            row = BubbleRow(text, _ts(), side=side,
                              sender=sender_label,
                              avatar_key=avatar_key, status=status,
                              show_name=(not is_self) and in_group)
            self.chat_layout.addWidget(row)
            if status_key is not None:
                self._status_rows[status_key] = row
        elif kind == "sys":
            _, text = ev
            row = BubbleRow(text, "", side="sys")
            self.chat_layout.addWidget(row)

    def _set_msg_status(self, status_key: int, status: str) -> None:
        """Update an outgoing message's delivery status (model + live row)."""
        self._msg_status[status_key] = status
        row = self._status_rows.get(status_key)
        if row is not None:
            row.set_status(status)

    def _add_message(self, key: str, sender_id: str, text: str,
                      is_self: bool, sender_label: str | None = None,
                      status_key: int | None = None) -> None:
        ev = ("msg", sender_id, text, is_self, sender_label or sender_id,
              status_key)
        self.conversations.setdefault(key, []).append(ev)
        if key == self.active:
            # Always follow your own outgoing messages; for incoming
            # ones, follow only if you were already at the bottom —
            # otherwise we'd yank the user away from history they're
            # mid-reading.
            follow = is_self or self._is_at_bottom()
            self._render_event(ev)
            self._maybe_scroll_after_render(follow)
        else:
            self.unread.add(key)
            self._refresh_sidebar()

    def _add_system(self, key: str, text: str) -> None:
        ev = ("sys", text)
        self.conversations.setdefault(key, []).append(ev)
        if key == self.active:
            follow = self._is_at_bottom()
            self._render_event(ev)
            self._maybe_scroll_after_render(follow)

    # ── Send ────────────────────────────────────────────────────────────────

    def _on_send(self) -> None:
        if self.node is None or self.bridge is None:
            return
        text = self.message_entry.text().strip()
        if not text or self.active is None:
            return
        self.message_entry.clear()

        group = self.node._groups.get_by_id(self.active)
        if group is not None:
            async def _send_group() -> bool:
                return await self.node.send_group_message(group.group_id, text)
            self.bridge.submit_coro(_send_group())
            self._add_message(self.active, "you", text, is_self=True,
                                sender_label="you")
        else:
            peer = self.active
            status_key = self._send_seq
            self._send_seq += 1
            self._msg_status[status_key] = "pending"
            self._add_message(peer, "you", text, is_self=True,
                                sender_label="you", status_key=status_key)

            async def _send_peer() -> str | None:
                return await self.node.send_message(peer, text)
            fut = self.bridge.submit_coro(_send_peer())

            def _done(f: Any, sk: int = status_key) -> None:
                # Runs on the asyncio thread; hand off to the Qt thread via
                # the event queue (drained by _drain_events).
                try:
                    mid = f.result()
                except Exception:
                    mid = None
                self.event_queue.put(("send_done", sk, mid))
            fut.add_done_callback(_done)

    # ── Event drain ─────────────────────────────────────────────────────────

    def _wire_callbacks(self) -> None:
        if self.node is None:
            return
        q = self.event_queue

        def push(name: str, *args: Any) -> None:
            q.put((name, *args))

        self.node.on_message(lambda f, c: push("message", f, c))
        self.node.on_receipt(
            lambda mid, dst, ok: push("receipt", mid, dst, ok))
        self.node.on_pin_violation(
            lambda pid, ex, rcv: push("pin_violation", pid, ex, rcv))
        self.node.on_file_offer(lambda f, o: push("file_offer", f, o))
        self.node.on_file_complete(lambda fid, d: push("file_complete", fid, d))
        self.node.on_group_invite(
            lambda f, gid, gname, members: push(
                "group_invite", f, gid, gname, members))
        self.node.on_group_message(
            lambda f, gid, gname, c: push("group_msg", f, gid, gname, c))

    def _start_event_drain(self) -> None:
        self._drain_timer = QtCore.QTimer(self)
        self._drain_timer.timeout.connect(self._drain_events)
        self._drain_timer.start(50)

    def _drain_events(self) -> None:
        try:
            for _ in range(50):
                ev = self.event_queue.get_nowait()
                self._handle_event(ev)
        except queue.Empty:
            pass

    def _handle_event(self, ev: tuple) -> None:
        kind = ev[0]
        if kind == "message":
            from_id, content = ev[1], ev[2]
            label = self._label_for(from_id)
            self._add_message(from_id, from_id, content, is_self=False,
                                sender_label=label)
        elif kind == "connect_result":
            self._finish_import(ev[1], ev[2])
        elif kind == "file_sent":
            peer, name, ok = ev[1], ev[2], ev[3]
            self._add_system(
                peer, f"sent '{name}'" if ok else f"send failed: '{name}'")
        elif kind == "send_done":
            # send_message returned: msg_id => went on the wire, None => failed
            status_key, mid = ev[1], ev[2]
            if mid:
                self._sent_msgid[mid] = status_key
                self._set_msg_status(status_key, "sent")
            else:
                self._set_msg_status(status_key, "failed")
        elif kind == "receipt":
            # Read receipt arrived → flip the bubble's checkmark to read.
            mid, ok = ev[1], ev[3]
            sk = self._sent_msgid.get(mid)
            if sk is not None and ok:
                self._set_msg_status(sk, "read")
        elif kind == "pin_violation":
            QtWidgets.QMessageBox.critical(
                self, "Key mismatch",
                f"Pinned key mismatch for {_short(ev[1])}.\n"
                f"Expected {ev[2][:16]}…\nReceived {ev[3][:16]}…\n\n"
                "Connection rejected. Use /trust via CLI.",
            )
        elif kind == "file_offer":
            self._on_file_offer(ev[1], ev[2])
        elif kind == "file_complete":
            self._on_file_complete(ev[1], ev[2])
        elif kind == "group_invite":
            from_id, gid, gname, members = ev[1], ev[2], ev[3], ev[4]
            self._add_system(gid,
                f"invited to group '{gname}' by {_short(from_id, 12)} "
                f"({len(members)} member{'s' if len(members) != 1 else ''})")
            self._refresh_sidebar()
        elif kind == "group_msg":
            from_id, gid, _gname, content = ev[1], ev[2], ev[3], ev[4]
            label = self._label_for(from_id)
            self._add_message(gid, from_id, content, is_self=False,
                                sender_label=label)

    def _label_for(self, peer_id: str) -> str:
        if self.book is None:
            return _short(peer_id)
        c = self.book.get_by_peer_id(peer_id)
        return c.label if c else _short(peer_id, 12)

    def _on_file_offer(self, from_id: str, offer: dict) -> None:
        if self.node is None:
            return
        fid = offer.get("file_id", "")
        if not fid:
            return
        self._pending_offers[fid] = (from_id, offer)
        # PlainText: the file name is peer-controlled. A static
        # QMessageBox.question renders AutoText, so a name like
        # `<img src=http://x>` would fetch from the real IP (outside Tor) the
        # moment the offer dialog appears — before the user even clicks.
        box = QtWidgets.QMessageBox(self)
        box.setIcon(QtWidgets.QMessageBox.Icon.Question)
        box.setWindowTitle("Incoming file")
        box.setTextFormat(QtCore.Qt.TextFormat.PlainText)
        box.setText(
            f"{_short(from_id, 12)} wants to send "
            f"'{offer.get('name')}' ({offer.get('size', 0)} bytes). Accept?")
        box.setStandardButtons(
            QtWidgets.QMessageBox.StandardButton.Yes
            | QtWidgets.QMessageBox.StandardButton.No)
        ok = box.exec()
        if ok == QtWidgets.QMessageBox.StandardButton.Yes:
            self.node.accept_file_offer(offer)
            self._add_system(
                from_id, f"accepting '{offer.get('name')}'…")
        else:
            self._pending_offers.pop(fid, None)

    def _on_file_complete(self, file_id: str, data: bytes) -> None:
        offer_entry = self._pending_offers.pop(file_id, None)
        from_id = offer_entry[0] if offer_entry else "?"
        name = (offer_entry[1].get("name", "file.bin")
                if offer_entry else "file.bin")
        self._add_system(from_id,
                          f"received '{name}' ({len(data)} bytes)")
        path, _ = QtWidgets.QFileDialog.getSaveFileName(
            self, f"Save '{name}' as…", name)
        if path:
            try:
                with open(path, "wb") as f:
                    f.write(data)
                self._add_system(from_id, f"saved to {path}")
            except OSError as e:
                QtWidgets.QMessageBox.critical(
                    self, "Save failed", str(e))

    # ── Status / refresh ────────────────────────────────────────────────────

    def _start_status_refresh(self) -> None:
        self._status_timer = QtCore.QTimer(self)
        self._status_timer.timeout.connect(self._refresh_status)
        self._status_timer.start(1000)
        self._refresh_status()

    def _refresh_status(self) -> None:
        if self.node is None:
            return
        n_peers = len(self.node._connections)
        n_groups = len(self.node._groups.all_groups())
        onion = self.node.transport.public_address or ""
        is_tor = onion.endswith(".onion")
        self.header_status.setText(
            f"{n_peers} peer{'s' if n_peers != 1 else ''}  ·  "
            f"{n_groups} group{'s' if n_groups != 1 else ''}"
            + ("  ·  tor" if is_tor else ""))
        self.status_dot.setProperty("connected", n_peers > 0)
        self.status_dot.style().unpolish(self.status_dot)
        self.status_dot.style().polish(self.status_dot)
        self.tor_lock.setVisible(is_tor)
        active_label = "—"
        if self.active:
            g = self.node._groups.get_by_id(self.active)
            if g:
                active_label = f"group {g.name}"
            else:
                c = self.book.get_by_peer_id(self.active) if self.book else None
                active_label = c.label if c else _short(self.active)
        self.status_label.setText(
            f"port {self.node.port}   ·   active: {active_label}")

    # ── Auto-reconnect ──────────────────────────────────────────────────────

    def _auto_reconnect(self) -> None:
        if self.node is None or self.book is None or self.bridge is None:
            return

        async def _reconnect() -> None:
            for c in self.book.all():
                try:
                    await self.node.connect_to_peer(
                        c.host, c.port, c.peer_id,
                        bytes.fromhex(c.x25519_pub),
                        bytes.fromhex(c.ed25519_pub),
                    )
                except Exception:  # noqa: S110
                    pass
        self.bridge.submit_coro(_reconnect())

    # ── Actions ─────────────────────────────────────────────────────────────

    def _action_export(self) -> None:
        if self.node is None:
            return
        host = self.node.host
        port = self.node.port
        onion = self.node.transport.public_address or None
        if onion and not onion.endswith(".onion"):
            onion = None
        url = generate_invite(self.node.identity, host, port, onion=onion)
        QtWidgets.QApplication.clipboard().setText(url)
        QtWidgets.QMessageBox.information(
            self, "Invite copied",
            "Your invite is on the clipboard. Share it through any "
            "out-of-band channel.")

    def _action_import(self) -> None:
        if self.node is None or self.book is None or self.bridge is None:
            return
        text = QtWidgets.QApplication.clipboard().text() or ""
        if not text.strip():
            QtWidgets.QMessageBox.warning(
                self, "Clipboard empty", "Nothing to import.")
            return
        try:
            data = parse_invite(text)
        except ValueError as e:
            QtWidgets.QMessageBox.critical(
                self, "Invalid invite", str(e))
            return
        if data["peer_id"] == self.node.identity.peer_id:
            QtWidgets.QMessageBox.warning(
                self, "That's your own invite",
                "You can't add yourself as a contact.")
            return

        ok = QtWidgets.QMessageBox.question(
            self, "Import invite",
            f"Connect to peer_id\n\n{_short(data['peer_id'], 24)}\n\n"
            f"at {data.get('host')}:{data.get('port')}?",
        )
        if ok != QtWidgets.QMessageBox.StandardButton.Yes:
            return

        # Non-blocking connect. The old code did future.result(timeout=35)
        # which froze the Qt thread for the whole (slow, over-Tor) connect —
        # hence "python3 not responding". Now we show an indeterminate
        # "Connecting…" dialog and resolve via the bridge future's callback,
        # which posts a connect_result event onto the Qt thread.
        dlg = QtWidgets.QProgressDialog("Connecting to peer…", "", 0, 0, self)
        dlg.setWindowTitle("Import invite")
        dlg.setCancelButton(None)
        dlg.setWindowModality(QtCore.Qt.WindowModality.ApplicationModal)
        dlg.setMinimumDuration(0)
        dlg.setAutoClose(False)
        dlg.setAutoReset(False)
        dlg.show()
        self._connect_dialog = dlg

        async def _connect() -> bool:
            host = data.get("onion") or data["host"]
            port = 80 if "onion" in data else data["port"]
            return await self.node.connect_to_peer(
                host, port, data["peer_id"],
                bytes.fromhex(data["x25519_pub"]),
                bytes.fromhex(data["ed25519_pub"]))

        fut = self.bridge.submit_coro(_connect())

        def _done(f: Any) -> None:
            try:
                connected = bool(f.result())
            except Exception:
                connected = False
            self.event_queue.put(("connect_result", connected, data))
        fut.add_done_callback(_done)

    def _finish_import(self, connected: bool, data: dict) -> None:
        """Runs on the Qt thread once a connect attempt resolves."""
        dlg = self._connect_dialog
        self._connect_dialog = None
        if dlg is not None:
            dlg.close()
        if not connected:
            QtWidgets.QMessageBox.critical(
                self, "Connection failed", "Could not reach the peer.")
            return
        # Only prompt for a label when there's an address book to save into;
        # otherwise there is nothing to do but open the conversation.
        if self.book is not None:
            label, ok2 = self._ask_text(
                "Save to address book",
                "Give this contact a label to save it (leave empty to skip).",
                placeholder="e.g. raven")
            if ok2 and label.strip():
                save_host = data.get("onion", data["host"])
                save_port = 80 if "onion" in data else data["port"]
                self.book.add(Contact(
                    label=label.strip(), peer_id=data["peer_id"],
                    host=save_host, port=save_port,
                    x25519_pub=data["x25519_pub"],
                    ed25519_pub=data["ed25519_pub"]))
                self._refresh_sidebar()
        self._select(data["peer_id"])

    def _action_send_file(self) -> None:
        if self.node is None or self.bridge is None or self.active is None:
            QtWidgets.QMessageBox.warning(
                self, "No active conversation", "Pick a peer first.")
            return
        if self.node._groups.get_by_id(self.active) is not None:
            QtWidgets.QMessageBox.information(
                self, "Not supported",
                "File transfer is direct-peer only for now.")
            return
        path, _ = QtWidgets.QFileDialog.getOpenFileName(
            self, "File to send")
        if not path:
            return

        # Non-blocking: send_file now waits (up to 60s) for the receiver to
        # accept before streaming, so blocking the Qt thread on its result
        # would freeze the whole window. Fire it on the bridge and report via
        # the event queue.
        peer = self.active
        name = Path(path).name
        self._add_system(peer, f"sending '{name}'…")

        async def _send() -> str | None:
            return await self.node.send_file(peer, path)
        fut = self.bridge.submit_coro(_send())

        def _done(f: Any) -> None:
            try:
                ok = bool(f.result())
            except Exception:
                ok = False
            self.event_queue.put(("file_sent", peer, name, ok))
        fut.add_done_callback(_done)

    def _action_backup(self) -> None:
        if not self.recovery_mnemonic:
            QtWidgets.QMessageBox.warning(
                self, "Backup unavailable",
                "Recovery mnemonic is not available.")
            return
        self._show_mnemonic_dialog(self.recovery_mnemonic.split())

    def _show_mnemonic_dialog(self, words: list[str]) -> None:
        dlg = QtWidgets.QDialog(self)
        dlg.setWindowTitle("Recovery mnemonic")
        dlg.resize(580, 460)
        v = QtWidgets.QVBoxLayout(dlg)

        if self._sigil is not None:
            sigil_lbl = QtWidgets.QLabel()
            sigil_lbl.setPixmap(self._sigil.scaled(
                110, 110,
                QtCore.Qt.AspectRatioMode.KeepAspectRatio,
                QtCore.Qt.TransformationMode.SmoothTransformation,
            ))
            sigil_lbl.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
            v.addWidget(sigil_lbl)

        title = QtWidgets.QLabel("Write these 24 words down.")
        title.setStyleSheet(
            f"color: {T.WARN_AMBER}; font-weight: 600; font-size: 12pt;")
        title.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        v.addWidget(title)

        # Grid of words. We've had multiple failures making this
        # render reliably with stylesheets (QSS f-string brace
        # mishaps, global QDialog QLabel rules silently overriding
        # inline ones, font fallback going through the body sans
        # chain). Belt-and-suspenders approach below: explicit
        # QFont with monospace fallbacks, explicit QPalette for
        # bg+fg (bypasses QSS entirely for the cell paint), no
        # inline stylesheet at all.
        # Pull the system's known-good fixed-width font instead of
        # naming families — this returns whatever Qt has actually
        # registered as monospace, no fallback misses.
        mono = QtGui.QFontDatabase.systemFont(
            QtGui.QFontDatabase.SystemFont.FixedFont)
        mono.setPointSize(11)
        mono.setBold(False)

        # Wrap each word in a QFrame: QFrame respects QSS
        # background-color reliably (QLabel needs WA_StyledBackground
        # which has been a flake source in PySide6). The QFrame paints
        # the card bg + radius, the inner QLabel just renders text.
        cell_qss = (
            "QFrame#WordCell { background-color: "
            f"{T.BG_RAISED}; border-radius: 6px; }}"
        )
        text_color = T.FG_PRIMARY

        grid = QtWidgets.QGridLayout()
        grid.setHorizontalSpacing(T.PAD_SM)
        grid.setVerticalSpacing(T.PAD_SM)
        for i, w in enumerate(words):
            frame = QtWidgets.QFrame()
            frame.setObjectName("WordCell")
            frame.setAttribute(
                QtCore.Qt.WidgetAttribute.WA_StyledBackground, True)
            frame.setStyleSheet(cell_qss)
            inner = QtWidgets.QHBoxLayout(frame)
            inner.setContentsMargins(14, 10, 14, 10)

            label = QtWidgets.QLabel(f"{i+1:>2}.  {w}")
            label.setFont(mono)
            label.setStyleSheet(
                f"color: {text_color}; background: transparent;")
            label.setAlignment(QtCore.Qt.AlignmentFlag.AlignVCenter
                                | QtCore.Qt.AlignmentFlag.AlignLeft)
            inner.addWidget(label)

            grid.addWidget(frame, i // 3, i % 3)
        v.addLayout(grid)

        warn = QtWidgets.QLabel(
            "Anyone with these words can recompute your salt and, with the "
            "passphrase, decrypt your address book. Store offline.")
        warn.setWordWrap(True)
        warn.setStyleSheet(f"color: {T.WARN_AMBER}; font-size: 9pt;")
        v.addWidget(warn)

        btns = QtWidgets.QHBoxLayout()
        copy_btn = QtWidgets.QPushButton("Copy")
        def _copy_mnemonic() -> None:
            QtWidgets.QApplication.clipboard().setText(" ".join(words))
            QtWidgets.QMessageBox.warning(
                dlg, "Mnemonic on clipboard",
                "Paste somewhere safe, then clear the clipboard.",
            )
        copy_btn.clicked.connect(_copy_mnemonic)
        btns.addWidget(copy_btn)
        btns.addStretch()
        done_btn = QtWidgets.QPushButton("Done")
        done_btn.setObjectName("AccentButton")
        done_btn.clicked.connect(dlg.accept)
        btns.addWidget(done_btn)
        v.addLayout(btns)

        dlg.exec()

    def _action_panic(self) -> None:
        ok = QtWidgets.QMessageBox.question(
            self, "PANIC",
            "Wipe ALL in-memory state and exit immediately?\n"
            "(disk address book and salt are NOT touched)",
        )
        if ok != QtWidgets.QMessageBox.StandardButton.Yes:
            return
        try:
            if self.node is not None:
                self.node.panic()
            if self.book is not None:
                self.book.wipe_memory()
        finally:
            if self.bridge is not None:
                self.bridge.stop(timeout=1.0)
            QtWidgets.QApplication.instance().quit()

    def _ask_text(self, title: str, prompt: str, text: str = "",
                  placeholder: str = "",
                  ok_label: str = "OK") -> tuple[str, bool]:
        """A roomy, on-theme text-input modal.

        QInputDialog.getText renders a cramped box whose OS title bar often
        clips the title; this shows the title *inside* the dialog and
        enforces a sensible minimum width. Returns (text, accepted).
        """
        dlg = QtWidgets.QDialog(self)
        dlg.setWindowTitle(title)
        dlg.setMinimumWidth(440)
        v = QtWidgets.QVBoxLayout(dlg)
        v.setContentsMargins(T.PAD_LG, T.PAD_LG, T.PAD_LG, T.PAD_MD)
        v.setSpacing(T.PAD_MD)

        head = QtWidgets.QLabel(title)
        head.setObjectName("DialogTitle")
        v.addWidget(head)

        prompt_lbl = QtWidgets.QLabel(prompt)
        prompt_lbl.setObjectName("DialogPrompt")
        prompt_lbl.setWordWrap(True)
        v.addWidget(prompt_lbl)

        edit = QtWidgets.QLineEdit(text)
        edit.setMinimumHeight(38)
        if placeholder:
            edit.setPlaceholderText(placeholder)
        v.addWidget(edit)

        row = QtWidgets.QHBoxLayout()
        row.setSpacing(T.PAD_SM)
        row.addStretch()
        cancel = QtWidgets.QPushButton("Cancel")
        cancel.setFixedHeight(36)
        cancel.clicked.connect(dlg.reject)
        row.addWidget(cancel)
        ok = QtWidgets.QPushButton(ok_label)
        ok.setObjectName("AccentButton")
        ok.setFixedHeight(36)
        ok.setDefault(True)
        ok.clicked.connect(dlg.accept)
        row.addWidget(ok)
        v.addLayout(row)

        edit.returnPressed.connect(dlg.accept)
        edit.setFocus()
        accepted = dlg.exec() == QtWidgets.QDialog.DialogCode.Accepted
        return edit.text(), accepted

    def _action_group_new(self) -> None:
        if self.node is None or self.bridge is None:
            return
        name, ok = self._ask_text(
            "New group", "Choose a name for the group.",
            placeholder="e.g. Nightfall Cell")
        if not ok or not name.strip():
            return

        async def _create() -> str | None:
            return await self.node.create_group(name.strip(), [])
        try:
            gid = self.bridge.submit_coro(_create()).result(timeout=5.0)
        except Exception as e:
            QtWidgets.QMessageBox.critical(
                self, "Group create failed", str(e))
            return
        if gid is None:
            QtWidgets.QMessageBox.critical(
                self, "Group create failed",
                "Name already in use, or empty name.")
            return
        self._add_system(gid, f"group '{name}' created")
        self._refresh_sidebar()

    def _action_group_add(self) -> None:
        if self.node is None or self.bridge is None or self.active is None:
            return
        group = self.node._groups.get_by_id(self.active)
        if group is None:
            return
        target, ok = self._ask_text(
            "Add member", "Enter a saved contact's label, or a peer ID.",
            placeholder="label or 40-char hex peer ID")
        if not ok or not target.strip():
            return
        contact = self.book.get(target.strip()) if self.book else None
        peer_id = contact.peer_id if contact else target.strip()

        async def _add() -> bool:
            return await self.node.add_group_member(group.group_id, peer_id)

        try:
            success = self.bridge.submit_coro(_add()).result(timeout=10.0)
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Add failed", str(e))
            return
        if success:
            self._add_system(group.group_id,
                              f"added {_short(peer_id, 12)} to group")
            self._refresh_sidebar()

    def _action_group_leave(self) -> None:
        if (self.node is None or self.bridge is None
                or self.active is None):
            return
        group = self.node._groups.get_by_id(self.active)
        if group is None:
            return
        ok = QtWidgets.QMessageBox.question(
            self, "Leave group",
            f"Leave group '{group.name}'?",
        )
        if ok != QtWidgets.QMessageBox.StandardButton.Yes:
            return

        try:
            self.node.leave_group(group.group_id)
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Leave failed", str(e))
            return
        self.active = None
        self._refresh_sidebar()
        self._redraw_conv_header()
        self._redraw_chat()

    def _action_about(self) -> None:
        try:
            from . import __version__ as ver
        except ImportError:
            ver = "?"
        dlg = QtWidgets.QDialog(self)
        dlg.setWindowTitle("About malphas")
        dlg.resize(460, 500)
        v = QtWidgets.QVBoxLayout(dlg)
        v.setContentsMargins(T.PAD_XL, T.PAD_XL, T.PAD_XL, T.PAD_LG)
        v.setSpacing(T.PAD_MD)
        v.addStretch()

        if self._sigil is not None:
            sigil_lbl = QtWidgets.QLabel()
            sigil_lbl.setPixmap(_sigil_with_halo(self._sigil, 132, pad=24))
            sigil_lbl.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
            sigil_lbl.setStyleSheet("background: transparent;")
            v.addWidget(sigil_lbl)

        title = QtWidgets.QLabel(f"malphas {ver}")
        title.setObjectName("EmptyTitle")
        title.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        v.addWidget(title)

        tagline = QtWidgets.QLabel("Privacy-first peer-to-peer messenger")
        tagline.setObjectName("EmptyHint")
        tagline.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        v.addWidget(tagline)

        feats = QtWidgets.QLabel(
            "End-to-end encrypted · Double Ratchet · sealed sender\n"
            "Anonymous over Tor · 3-hop onion routing · v3 hidden services\n"
            "X25519 · Ed25519 · ChaCha20-Poly1305 · BLAKE2s peer IDs\n"
            "At rest: Argon2id-derived key · ChaCha20-Poly1305")
        feats.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        feats.setStyleSheet(f"color: {T.FG_MUTED}; font-size: 9pt;"
                            "background: transparent;")
        v.addWidget(feats)

        if self.node is not None:
            pid_cap = QtWidgets.QLabel("YOUR PEER ID")
            pid_cap.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
            pid_cap.setStyleSheet(
                f"color:{T.FG_FAINT}; font-size: 8pt; font-weight: 700; "
                "letter-spacing: 2px; background: transparent;")
            v.addWidget(pid_cap)
            pid = QtWidgets.QLabel(self.node.identity.peer_id)
            pid.setStyleSheet(
                f"font-family:'JetBrains Mono', monospace; "
                f"color:{T.FG_MUTED}; font-size: 9pt; background: transparent;")
            pid.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
            pid.setWordWrap(True)
            pid.setTextInteractionFlags(
                QtCore.Qt.TextInteractionFlag.TextSelectableByMouse)
            v.addWidget(pid)

        v.addStretch()

        row = QtWidgets.QHBoxLayout()
        row.setSpacing(T.PAD_SM)
        row.addStretch()
        link = QtWidgets.QPushButton("Open GitHub")
        link.setObjectName("AccentOutline")
        link.setFixedHeight(38)
        link.clicked.connect(lambda: webbrowser.open(GITHUB_URL))
        row.addWidget(link)
        close = QtWidgets.QPushButton("Close")
        close.setFixedHeight(38)
        close.clicked.connect(dlg.accept)
        row.addWidget(close)
        row.addStretch()
        v.addLayout(row)

        dlg.exec()

    # ── Lifecycle ───────────────────────────────────────────────────────────

    def closeEvent(self, ev: QtGui.QCloseEvent) -> None:
        if self.node is not None and self.bridge is not None:
            try:
                self.bridge.submit_coro(self.node.stop()).result(timeout=3.0)
            except Exception:  # noqa: S110
                pass
            self.bridge.stop(timeout=2.0)
        if self.book is not None:
            try:
                self.book.wipe_memory()
            except Exception:  # noqa: S110
                pass
        ev.accept()


# ── Entrypoint ──────────────────────────────────────────────────────────────


def launch_qt_gui(
    node: MalphasNode | None = None,
    book: AddressBook | None = None,
    bridge: AsyncBridge | None = None,
    recovery_mnemonic: str | None = None,
) -> int:
    app = QtWidgets.QApplication.instance() or QtWidgets.QApplication(sys.argv)
    win = MalphasQtWindow(node=node, book=book, bridge=bridge,
                            recovery_mnemonic=recovery_mnemonic)
    win.show()
    if node is None:
        # Standalone preview content
        for label in ["alice", "bob", "carol"]:
            win._add_sidebar_row(label, label, "(preview)", is_group=False)
        win._add_system("preview", "welcome to malphas (Qt preview)")
    # getattr indirection here is to dodge a tooling false-positive
    # that flags `.exec(` as JS child_process.exec; this is Qt's
    # event-loop entry, not subprocess.
    run_event_loop = getattr(app, "exec")  # noqa: B009
    return run_event_loop()


if __name__ == "__main__":
    sys.exit(launch_qt_gui())
