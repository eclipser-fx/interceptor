"""Auditor deliverables: evidence packs and journal statistics.

An evidence pack is a self-contained, shareable bundle — verification result,
operational audit, and the signed events themselves — in JSON for machines or
a single HTML file for humans. The pack states its own verification outcome
up front; a pack built from a tampered journal says so instead of silently
omitting the failure.
"""

from __future__ import annotations

import dataclasses
import html
import json
from pathlib import Path
from typing import Any

from .audit import InvocationStatus, audit_verified_snapshot
from .errors import EvidenceAuditError
from .journal import utc_timestamp
from .verification import JournalSnapshot, PublicKeys, load_journal_snapshot

EVIDENCE_PACK_FORMAT = "interceptor-evidence-pack/1"


def export_journal(path: Path, public_keys: PublicKeys) -> dict[str, Any]:
    """Build a JSON-serializable evidence pack for the journal at *path*."""
    snapshot = load_journal_snapshot(path, public_keys)
    verification = snapshot.verification
    try:
        audit = audit_verified_snapshot(snapshot)
        invocations: list[dict[str, Any]] = []
        for inv in audit.invocations:
            record = dataclasses.asdict(inv)
            status = record["status"]
            record["status"] = status.value if isinstance(status, InvocationStatus) else status
            invocations.append(record)
        audit_payload: dict[str, Any] | None = {
            "structurally_valid": audit.structurally_valid,
            "needs_reconciliation": audit.needs_reconciliation,
            "invocations": invocations,
            "issues": [dataclasses.asdict(issue) for issue in audit.issues],
        }
    except EvidenceAuditError as exc:
        audit_payload = None
        audit_error = str(exc)
    else:
        audit_error = ""
    return {
        "format": EVIDENCE_PACK_FORMAT,
        "exported_at": utc_timestamp(),
        "journal": str(path),
        "verification": {
            "valid": verification.valid,
            "events_verified": verification.events_verified,
            "issues": [dataclasses.asdict(issue) for issue in verification.issues],
        },
        "audit": audit_payload,
        "audit_error": audit_error,
        "events": list(snapshot.events),
    }


def journal_stats(snapshot: JournalSnapshot) -> dict[str, Any]:
    """Operational counts over an already-verified snapshot (no audit needed)."""
    by_status: dict[str, int] = {status.value: 0 for status in InvocationStatus}
    by_action: dict[str, int] = {}
    by_risk: dict[str, int] = {}
    decisions = outcomes = resolutions = countersignatures = checkpoints = 0
    archives = 0
    for event in snapshot.events:
        event_type = event.get("event_type")
        if event_type == "decision":
            decisions += 1
            action = str(event.get("action_name", "<unknown>"))
            by_action[action] = by_action.get(action, 0) + 1
            risk = str(event.get("risk", "<unknown>"))
            by_risk[risk] = by_risk.get(risk, 0) + 1
        elif event_type == "outcome":
            outcomes += 1
            status = str(event.get("status", "<unknown>"))
            by_status[status] = by_status.get(status, 0) + 1
        elif event_type == "resolution":
            resolutions += 1
        elif event_type == "countersignature":
            countersignatures += 1
        elif event_type == "checkpoint":
            checkpoints += 1
        elif event_type == "archive":
            archives += 1
    return {
        "events": len(snapshot.events),
        "decisions": decisions,
        "outcomes": outcomes,
        "resolutions": resolutions,
        "countersignatures": countersignatures,
        "checkpoints": checkpoints,
        "archives": archives,
        "by_action": by_action,
        "by_risk": by_risk,
        "by_outcome_status": by_status,
    }


def render_html(bundle: dict[str, Any]) -> str:
    """A single self-contained HTML report for an evidence pack."""
    verification = bundle["verification"]
    audit = bundle["audit"]
    rows: list[str] = []
    if audit is not None:
        for inv in audit["invocations"]:
            rows.append(
                "<tr><td>{action}</td><td>{status}</td><td>{decision}</td>"
                "<td>{when}</td></tr>".format(
                    action=html.escape(str(inv["action_name"])),
                    status=html.escape(str(inv["status"])),
                    decision=html.escape(str(inv["decision"])),
                    when=html.escape(str(inv["decision_timestamp_utc"])),
                )
            )
    issues = "".join(
        f"<li>[{html.escape(str(i['code']))}] {html.escape(str(i['message']))}</li>"
        for i in verification["issues"]
    ) + "".join(
        f"<li>[{html.escape(str(i['code']))}] {html.escape(str(i['message']))}</li>"
        for i in (audit["issues"] if audit is not None else [])
    )
    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Evidence pack</title>
<style>body{{font-family:sans-serif;max-width:60rem;margin:2rem auto;padding:0 1rem}}
table{{border-collapse:collapse;width:100%}}
td,th{{border:1px solid #ccc;padding:.4rem;text-align:left}}
.ok{{color:#0a0}}.bad{{color:#a00}}</style></head>
<body>
<h1>Evidence pack</h1>
<p>Journal: {html.escape(str(bundle["journal"]))}<br>
Exported: {html.escape(str(bundle["exported_at"]))}</p>
<h2>Verification</h2>
<p class="{"ok" if verification["valid"] else "bad"}">
{"VALID" if verification["valid"] else "INVALID"} —
{int(verification["events_verified"])} events verified.</p>
<h2>Invocations</h2>
<table><tr><th>Action</th><th>Status</th><th>Decision</th><th>When</th></tr>
{"".join(rows) if rows else "<tr><td colspan='4'>(none)</td></tr>"}</table>
<h2>Issues</h2>
<ul>{issues if issues else "<li>(none)</li>"}</ul>
</body>
</html>
"""


def write_pack(bundle: dict[str, Any], output: Path, fmt: str) -> Path:
    """Write *bundle* as JSON or HTML to *output* (parents created)."""
    output.parent.mkdir(parents=True, exist_ok=True)
    if fmt == "html":
        output.write_text(render_html(bundle), encoding="utf-8")
    else:
        output.write_text(json.dumps(bundle, indent=2, sort_keys=True), encoding="utf-8")
    return output
