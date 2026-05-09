"""
Smoke tests for the Tkinter GUI (v0.10.0).

Tk mainloop is interactive and requires an X display. CI runs
headless. We test:
  • The AsyncBridge lifecycle (start, submit_coro, stop) — pure
    threading + asyncio, no Tk required.
  • The module imports (a missing import or a syntax error in
    gui.py would surface here).
  • Helpers (_short, _ts).

Full GUI E2E is out of scope; would need Xvfb + GUI driver.
"""

from __future__ import annotations

import asyncio
import os
import time

import pytest

from malphas.gui import AsyncBridge, _short, _ts

# ── AsyncBridge ──────────────────────────────────────────────────────────────


def test_bridge_starts_and_stops_cleanly():
    bridge = AsyncBridge()
    assert bridge.loop is not None
    assert bridge.loop.is_running()
    bridge.stop(timeout=2.0)


def test_bridge_submits_coroutine_and_returns_result():
    bridge = AsyncBridge()
    try:
        async def _add(x: int, y: int) -> int:
            await asyncio.sleep(0)
            return x + y

        future = bridge.submit_coro(_add(2, 3))
        assert future.result(timeout=2.0) == 5
    finally:
        bridge.stop(timeout=2.0)


def test_bridge_submit_after_stop_raises():
    bridge = AsyncBridge()
    bridge.stop(timeout=2.0)
    # The loop has stopped; submitting should raise or fail.
    async def _noop() -> None:
        return None

    # Either RuntimeError from a stopped loop or the future
    # never completes — accept both.
    try:
        future = bridge.submit_coro(_noop())
        with pytest.raises((RuntimeError, asyncio.CancelledError, TimeoutError)):
            future.result(timeout=0.5)
    except RuntimeError:
        pass  # acceptable too


def test_bridge_two_independent_calls_dont_collide():
    bridge = AsyncBridge()
    try:
        async def _slow(n: int) -> int:
            await asyncio.sleep(0.05)
            return n * 2

        f1 = bridge.submit_coro(_slow(10))
        f2 = bridge.submit_coro(_slow(20))
        assert f1.result(timeout=2.0) == 20
        assert f2.result(timeout=2.0) == 40
    finally:
        bridge.stop(timeout=2.0)


# ── Helpers ──────────────────────────────────────────────────────────────────


def test_short_truncates_long_strings():
    assert _short("a" * 32, n=8) == "aaaaaaaa…"
    assert _short("abc") == "abc"  # shorter than default n


def test_ts_format():
    s = _ts()
    assert len(s) == 5
    assert s[2] == ":"
    h, m = s.split(":")
    assert 0 <= int(h) <= 23
    assert 0 <= int(m) <= 59


# ── Construction (no mainloop) ───────────────────────────────────────────────

@pytest.mark.skipif(
    not os.environ.get("DISPLAY") and not os.environ.get("WAYLAND_DISPLAY"),
    reason="no display available — Tk widget construction would fail",
)
def test_gui_constructs_without_running_mainloop():
    """Building the GUI tree should not crash. We don't enter mainloop."""
    from unittest.mock import MagicMock

    from malphas.gui import MalphasGUI

    node = MagicMock()
    node.identity.peer_id = "a" * 40
    node.port = 7777
    node.host = "127.0.0.1"
    node.transport.public_address = None
    node._connections = {}
    node._groups.all_groups.return_value = []
    node._groups.get_by_id.return_value = None
    node.discovery.all_peers.return_value = []
    book = MagicMock()
    book.all.return_value = []
    bridge = AsyncBridge()
    try:
        gui = MalphasGUI(node, book, bridge)
        # Tear down without entering mainloop.
        gui.root.destroy()
    finally:
        bridge.stop(timeout=2.0)
