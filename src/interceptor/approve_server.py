"""Human approval over the local network: approve from a browser or phone.

:class:`ApprovalServer` runs a tiny token-authenticated HTTP UI (standard
library only) listing pending approval requests with Allow/Deny buttons, and
the matching :class:`ServerApprovalProvider` blocks the guarded call until an
operator decides or the request times out (fail closed).

Scope this honestly: it is loopback/LAN on-call tooling, not a hardened web
service. The page URL carries a bearer token (keep it out of chat, logs, and
history — anyone holding it can approve), there is no TLS, and the default
attribution is ``"web"``. For attributable approvals, compose with
:class:`interceptor.policy.AttestedApprovalProvider` and treat the URL like a
password. Each pending request additionally carries a single-use decision
token so a forged cross-site POST without the page cannot decide it.

The provider only ever sees :class:`ApprovalRequest` — the redacted summary,
never raw arguments — so the page cannot leak what the journal does not hold.
Binds to loopback by default; pass ``host="0.0.0.0"`` to approve from another
device on the LAN, keeping the printed URL (which carries the token) private.
"""

from __future__ import annotations

import html
import secrets
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .approval import (
    DECISION_ALLOWED,
    DECISION_DENIED,
    ApprovalDecision,
    ApprovalRequest,
)


@dataclass
class _Pending:
    request: ApprovalRequest
    created_at: float
    decided: threading.Event = field(default_factory=threading.Event)
    decision: ApprovalDecision | None = None
    decision_token: str = ""


class ApprovalServer:
    """Token-authenticated approval UI and the rendezvous for providers."""

    def __init__(
        self,
        *,
        host: str = "127.0.0.1",
        port: int = 0,
        request_ttl_seconds: float = 900,
        clock: Any = None,
    ) -> None:
        self._token = secrets.token_urlsafe(32)
        self._ttl = request_ttl_seconds
        self._clock = clock or time.monotonic
        self._lock = threading.Lock()
        self._pending: dict[str, _Pending] = {}
        self._counter = 0
        handler = self._make_handler()
        self._httpd = ThreadingHTTPServer((host, port), handler)
        self._httpd.daemon_threads = True
        self._thread = threading.Thread(
            target=self._httpd.serve_forever, daemon=True, name="interceptor-approval"
        )
        self._thread.start()

    @property
    def url(self) -> str:
        """The operator URL (carries the auth token — keep it private)."""
        host, port = self._httpd.server_address[:2]
        if isinstance(host, bytes):
            host = host.decode("ascii", "ignore")
        return f"http://{host}:{port}/?token={self._token}"

    @property
    def port(self) -> int:
        return int(self._httpd.server_address[1])

    def close(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
        self._thread.join(timeout=5)

    def __enter__(self) -> ApprovalServer:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    # -- provider side ----------------------------------------------------

    def register(self, request: ApprovalRequest) -> tuple[str, _Pending]:
        with self._lock:
            self._counter += 1
            pending_id = f"req-{self._counter}"
            pending = _Pending(
                request=request,
                created_at=self._clock(),
                decision_token=secrets.token_urlsafe(16),
            )
            self._pending[pending_id] = pending
            self._sweep_locked()
            return pending_id, pending

    def await_decision(self, pending_id: str, timeout: float) -> ApprovalDecision:
        with self._lock:
            pending = self._pending.get(pending_id)
        if pending is None:  # expired and swept while registering (clock skew in tests)
            return ApprovalDecision(DECISION_DENIED, "approval request expired")
        decided = pending.decided.wait(timeout)
        with self._lock:
            self._pending.pop(pending_id, None)
        if not decided or pending.decision is None:
            return ApprovalDecision(
                DECISION_DENIED,
                f"no operator decision within {timeout:g}s; failing closed",
            )
        return pending.decision

    def _sweep_locked(self) -> None:
        now = self._clock()
        expired = [
            pending_id
            for pending_id, pending in self._pending.items()
            if now - pending.created_at > self._ttl and not pending.decided.is_set()
        ]
        for pending_id in expired:
            pending = self._pending.pop(pending_id)
            pending.decision = ApprovalDecision(DECISION_DENIED, "approval request expired")
            pending.decided.set()

    # -- HTTP side --------------------------------------------------------

    def _decide(self, pending_id: str, allow: bool, by: str, decision_token: str) -> bool:
        with self._lock:
            pending = self._pending.get(pending_id)
            if pending is None or pending.decided.is_set():
                return False
            if not secrets.compare_digest(decision_token, pending.decision_token):
                return False
            pending.decision = ApprovalDecision(
                DECISION_ALLOWED if allow else DECISION_DENIED,
                f"decided by operator ({by or 'web'})",
                approved_by=by or "web",
            )
            pending.decided.set()
            return True

    def _snapshot(self) -> list[tuple[str, _Pending]]:
        with self._lock:
            self._sweep_locked()
            return list(self._pending.items())

    def _make_handler(self) -> type[BaseHTTPRequestHandler]:
        server = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:  # quiet
                pass

            def _denied(self) -> None:
                self.send_response(403)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"forbidden")

            def _authed(self, query: dict[str, list[str]]) -> bool:
                return secrets.compare_digest(query.get("token", [""])[0], server._token)

            def do_GET(self) -> None:
                parsed = urllib.parse.urlparse(self.path)
                query = urllib.parse.parse_qs(parsed.query)
                if not self._authed(query):
                    self._denied()
                    return
                rows = []
                for pending_id, pending in server._snapshot():
                    req = pending.request
                    rows.append(
                        f"<tr><td>{html.escape(pending_id)}</td><td>{html.escape(req.action_name)}</td><td>{html.escape(req.risk)}</td>"
                        f"<td>{html.escape(req.redacted_input_summary)}</td>"
                        "<td><form method='post' action='/decide'>"
                        f"<input type='hidden' name='token' value='{html.escape(server._token)}'>"
                        f"<input type='hidden' name='id' value='{html.escape(pending_id)}'>"
                        f"<input type='hidden' name='req_token' value='"
                        f"{html.escape(pending.decision_token)}'>"
                        "<button name='decision' value='allow'>Allow</button>"
                        "<button name='decision' value='deny'>Deny</button>"
                        "</form></td></tr>"
                    )
                body = (
                    "<!DOCTYPE html><html><head><meta charset='utf-8'>"
                    "<meta name='viewport' content='width=device-width'>"
                    "<title>Approvals</title></head><body>"
                    "<h1>Pending approvals</h1>"
                    "<table border='1' cellpadding='6'>"
                    "<tr><th>ID</th><th>Action</th><th>Risk</th><th>Input</th><th></th></tr>"
                    + ("".join(rows) if rows else "<tr><td colspan='5'>(none)</td></tr>")
                    + "</table></body></html>"
                ).encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self) -> None:
                if urllib.parse.urlparse(self.path).path != "/decide":
                    self.send_response(404)
                    self.end_headers()
                    return
                length = int(self.headers.get("Content-Length", "0"))
                form = urllib.parse.parse_qs(self.rfile.read(length).decode())
                if not secrets.compare_digest(form.get("token", [""])[0], server._token):
                    self._denied()
                    return
                pending_id = form.get("id", [""])[0]
                ok = server._decide(
                    pending_id,
                    form.get("decision", [""])[0] == "allow",
                    form.get("by", ["web"])[0][:120],
                    form.get("req_token", [""])[0],
                )
                self.send_response(200 if ok else 410)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"recorded" if ok else b"gone")

        return Handler


class ServerApprovalProvider:
    """Block the guarded call until an operator clicks Allow/Deny in the server UI.

    Times out fail-closed after *timeout_seconds*. Print ``server.url`` to the
    operator; the URL carries the auth token. Decisions are attributed to
    ``"web"`` (or the ``by`` form field) — wrap this provider in
    :class:`interceptor.policy.AttestedApprovalProvider` when the journal must
    say *who* approved.
    """

    def __init__(self, server: ApprovalServer, timeout_seconds: float = 300) -> None:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self._server = server
        self._timeout = timeout_seconds

    def decide(self, request: ApprovalRequest) -> ApprovalDecision:
        pending_id, _ = self._server.register(request)
        return self._server.await_decision(pending_id, self._timeout)
