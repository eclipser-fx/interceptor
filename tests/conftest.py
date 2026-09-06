"""Shared fixtures.

The ``_no_network`` fixture is autouse and global: it replaces socket creation
with a hard failure for the entire suite. The library's central claim is that
it does not talk to anything, and the only way to keep that true as the code
changes is to make a socket impossible to open while any test runs.
"""

from __future__ import annotations

import socket
from pathlib import Path
from typing import Any

import pytest

from interceptor.engine import reset_idempotency_state
from interceptor.journal import reset_precheck_cache
from interceptor.observer import reset_notifications

_REAL_SOCKET = socket.socket
_REAL_CREATE_CONNECTION = socket.create_connection


class NetworkAttemptError(RuntimeError):
    """Raised when anything under test tries to open a socket."""


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def blocked(*args: Any, **kwargs: Any):
        raise NetworkAttemptError("network access attempted")

    monkeypatch.setattr(socket, "socket", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)


@pytest.fixture
def allow_socket_creation(monkeypatch: pytest.MonkeyPatch) -> None:
    """Re-enable socket creation for tests that need an asyncio event loop.

    The ``_no_network`` fixture blocks every socket, but an asyncio loop cannot
    even be created without a ``socketpair`` self-pipe. Async wrapper tests
    therefore re-enable sockets locally; the guard itself is still covered by
    the blocked sync suite, which is where its no-network claim is enforced.
    """
    monkeypatch.setattr(socket, "socket", _REAL_SOCKET)
    monkeypatch.setattr(socket, "create_connection", _REAL_CREATE_CONNECTION)


@pytest.fixture(autouse=True)
def _reset_observer_state() -> None:
    """Observer notifications are once-per-process; tests need a clean slate."""
    reset_notifications()
    reset_idempotency_state()
    reset_precheck_cache()
    yield
    reset_notifications()
    reset_idempotency_state()
    reset_precheck_cache()


@pytest.fixture
def evidence_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """An isolated evidence home, so tests never touch the real one."""
    home = tmp_path / "evidence-home"
    home.mkdir()
    monkeypatch.setenv("INTERCEPTOR_EVIDENCE_HOME", str(home))
    return home
