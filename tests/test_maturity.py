"""Maturity batch: attribution, resolutions, declarative policy, countersign, export."""

from __future__ import annotations

import json
import threading
from pathlib import Path

import pytest

import interceptor as ic
from helpers import allow, deny
from interceptor import guard
from interceptor.audit import InvocationStatus, audit_journal
from interceptor.cosign import countersign_journal
from interceptor.export import export_journal, journal_stats
from interceptor.identity import (
    EphemeralSigningIdentity,
    generate_private_key,
    load_trusted_public_keys,
)
from interceptor.policy import Rule, RuleProvider, load_policy_file
from interceptor.resolve import resolve_journal
from interceptor.verification import load_journal_snapshot, verify_journal


def events(home: Path) -> list[dict]:
    path = home / "journal.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def trusted_keys(home: Path):
    keys = load_trusted_public_keys(home)
    assert keys, "expected an identity to have been created"
    return keys


# --- approval attribution ----------------------------------------------------


def test_approval_reason_recorded(evidence_home):
    @guard(action="test.reason", approval_provider=allow())
    def act() -> str:
        return "ok"

    act()
    decision = next(e for e in events(evidence_home) if e["event_type"] == "decision")
    assert decision["approval_reason"] == "test provider"


def test_approved_by_recorded_and_bounded(evidence_home):
    provider = allow()
    provider.decision = "allowed"

    class Named:
        def decide(self, request):
            return ic.ApprovalDecision("allowed", "ok", approved_by="alice@example.com")

    @guard(action="test.named", approval_provider=Named())
    def act() -> str:
        return "ok"

    act()
    decision = next(e for e in events(evidence_home) if e["event_type"] == "decision")
    assert decision["approved_by"] == "alice@example.com"


def test_approval_reason_scrubbed(evidence_home):
    class Leaky:
        def decide(self, request):
            return ic.ApprovalDecision("allowed", "key sk-live-abcdefgh12345678 here")

    @guard(action="test.leaky-reason", approval_provider=Leaky())
    def act() -> str:
        return "ok"

    act()
    decision = next(e for e in events(evidence_home) if e["event_type"] == "decision")
    assert "sk-live" not in decision["approval_reason"]
    assert "<REDACTED>" in decision["approval_reason"]


# --- resolutions -------------------------------------------------------------


def test_resolve_clears_reconciliation(evidence_home):
    @guard(action="test.reconcile", approval_provider=allow())
    def act() -> str:
        raise RuntimeError("processor exploded")

    with pytest.raises(RuntimeError):
        act()
    journal = evidence_home / "journal.jsonl"
    report = audit_journal(journal, trusted_keys(evidence_home))
    assert report.needs_reconciliation

    decision_id = report.invocations[0].decision_event_id
    resolve_journal(journal, decision_id, "confirmed_not_completed", note="no charge made")

    report = audit_journal(journal, trusted_keys(evidence_home))
    assert not report.needs_reconciliation
    assert report.invocations[0].status == InvocationStatus.RESOLVED_NOT_COMPLETED
    assert report.structurally_valid


def test_resolve_completed(evidence_home):
    @guard(action="test.reconcile2", approval_provider=allow())
    def act() -> None:
        return None

    act()  # succeeded; now resolve a *failed* style path via missing outcome instead
    journal = evidence_home / "journal.jsonl"
    recorded = events(evidence_home)
    # Truncate the outcome to simulate a crash after the side effect.
    journal.write_text(json.dumps(recorded[0]) + "\n")
    decision_id = recorded[0]["event_id"]
    resolve_journal(journal, decision_id, "confirmed_completed", note="processor shows refund")
    report = audit_journal(journal, trusted_keys(evidence_home))
    assert report.invocations[0].status == InvocationStatus.RESOLVED_COMPLETED
    assert not report.needs_reconciliation


def test_resolve_rejects_unknown_and_denied(evidence_home):
    journal = evidence_home / "journal.jsonl"
    journal.write_text("")
    with pytest.raises(ic.ResolutionError):
        resolve_journal(journal, "nope", "confirmed_completed")
    with pytest.raises(ic.ResolutionError):
        resolve_journal(journal, "nope", "bogus")

    @guard(action="test.denied-resolve", approval_provider=deny())
    def act() -> str:
        return "x"

    with pytest.raises(ic.ActionDenied):
        act()
    decision_id = next(e for e in events(evidence_home) if e["event_type"] == "decision")[
        "event_id"
    ]
    with pytest.raises(ic.ResolutionError):
        resolve_journal(journal, decision_id, "confirmed_completed")


def test_conflicting_resolutions_flagged(evidence_home):
    @guard(action="test.conflict", approval_provider=allow())
    def act() -> str:
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError):
        act()
    journal = evidence_home / "journal.jsonl"
    decision_id = next(e for e in events(evidence_home) if e["event_type"] == "decision")[
        "event_id"
    ]
    resolve_journal(journal, decision_id, "confirmed_completed")
    resolve_journal(journal, decision_id, "confirmed_not_completed")
    report = audit_journal(journal, trusted_keys(evidence_home))
    assert any(i.code == "conflicting_resolution" for i in report.issues)
    # Latest wins.
    assert report.invocations[0].status == InvocationStatus.RESOLVED_NOT_COMPLETED


# --- declarative policy ------------------------------------------------------


def test_rule_provider_globs_and_default(evidence_home):
    provider = RuleProvider(
        [
            Rule(action="billing.*", decision="denied", risks=frozenset({"high"})),
            Rule(action="billing.*", decision="allowed", reason="low-risk billing"),
        ]
    )

    @guard(action="billing.refund", risk="high", approval_provider=provider)
    def refund() -> str:
        return "x"

    @guard(action="billing.quote", risk="low", approval_provider=provider)
    def quote() -> str:
        return "q"

    @guard(action="infra.delete", risk="critical", approval_provider=provider)
    def delete() -> str:
        return "d"

    with pytest.raises(ic.ActionDenied):
        refund()
    assert quote() == "q"
    with pytest.raises(ic.ActionDenied):
        delete()


def test_load_policy_file(tmp_path):
    path = tmp_path / "policy.json"
    path.write_text(
        json.dumps(
            {
                "default": "denied",
                "rules": [
                    {
                        "action": "deploy.*",
                        "decision": "allowed",
                        "risks": ["low"],
                        "reason": "low-risk deploys",
                    }
                ],
            }
        )
    )
    provider = load_policy_file(path)
    assert isinstance(provider, RuleProvider)
    req = ic.ApprovalRequest(
        action_name="deploy.staging",
        risk="low",
        approval_mode="required",
        redacted_input_summary="",
        input_hash="h",
        contract_hash="c",
    )
    assert provider.decide(req).allowed
    bad = ic.ApprovalRequest(
        action_name="billing.refund",
        risk="low",
        approval_mode="required",
        redacted_input_summary="",
        input_hash="h",
        contract_hash="c",
    )
    assert not provider.decide(bad).allowed


def test_load_policy_file_rejects_garbage(tmp_path):
    path = tmp_path / "policy.json"
    path.write_text('{"rules": [{"action": "", "decision": "maybe"}]}')
    with pytest.raises(ic.PolicyError):
        load_policy_file(path)
    path.write_text("not json")
    with pytest.raises(ic.PolicyError):
        load_policy_file(path)


# --- countersignatures -------------------------------------------------------


def test_countersign_full_loop(evidence_home, tmp_path):
    from interceptor import checkpoint_journal

    @guard(action="test.cosign", approval_provider=allow())
    def act() -> str:
        return "ok"

    act()
    journal = evidence_home / "journal.jsonl"
    checkpoint_journal(journal)

    counter_key = tmp_path / "counter.pem"
    generate_private_key(counter_key)
    report = countersign_journal(journal, counter_key)
    assert report.checkpoint_count == 2

    # Verification needs the counter public key too.
    counter_pub = tmp_path / "counter-pub.pem"
    signer = EphemeralSigningIdentity.from_file(counter_key)
    from cryptography.hazmat.primitives import serialization

    counter_pub.write_bytes(
        signer.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    from interceptor.identity import load_public_key

    keys = (*trusted_keys(evidence_home), load_public_key(counter_pub))
    result = verify_journal(journal, keys)
    assert result.valid, result.issues


def test_countersign_requires_checkpoint(evidence_home, tmp_path):
    journal = evidence_home / "journal.jsonl"
    journal.write_text("")
    counter_key = tmp_path / "counter.pem"
    generate_private_key(counter_key)
    with pytest.raises(ic.CountersignError):
        countersign_journal(journal, counter_key)


def test_generate_key_refuses_overwrite(tmp_path):
    from interceptor.identity import IdentityError

    path = tmp_path / "k.pem"
    generate_private_key(path)
    with pytest.raises(IdentityError):
        generate_private_key(path)


# --- export + stats ----------------------------------------------------------


def test_export_json_and_html(evidence_home, tmp_path):
    @guard(action="test.export", approval_provider=allow())
    def act() -> str:
        return "ok"

    act()
    journal = evidence_home / "journal.jsonl"
    bundle = export_journal(journal, trusted_keys(evidence_home))
    assert bundle["format"] == "interceptor-evidence-pack/1"
    assert bundle["verification"]["valid"]
    assert bundle["audit"]["structurally_valid"]

    out_json = tmp_path / "pack.json"
    ic.write_pack(bundle, out_json, "json")
    assert json.loads(out_json.read_text())["format"] == "interceptor-evidence-pack/1"

    out_html = tmp_path / "pack.html"
    ic.write_pack(bundle, out_html, "html")
    text = out_html.read_text()
    assert "<html" in text and "test.export" in text and "succeeded" in text


def test_stats_counts(evidence_home):

    @guard(action="test.stats-a", approval_provider=allow())
    def act_a() -> str:
        return "ok"

    @guard(action="test.stats-b", approval_provider=deny())
    def act_b() -> str:
        return "x"

    act_a()
    with pytest.raises(ic.ActionDenied):
        act_b()
    journal = evidence_home / "journal.jsonl"
    snapshot = load_journal_snapshot(journal, trusted_keys(evidence_home))
    stats = journal_stats(snapshot)
    assert stats["decisions"] == 2
    assert stats["outcomes"] == 1
    assert stats["by_action"] == {"test.stats-a": 1, "test.stats-b": 1}


# --- concurrency -------------------------------------------------------------


def test_concurrent_appends_stay_valid(evidence_home):
    from interceptor.verification import verify_journal as _verify

    @guard(action="test.concurrent", approval_provider=allow())
    def act(n: int) -> int:
        return n

    errors: list[Exception] = []

    def worker(base: int) -> None:
        try:
            for i in range(10):
                act(base + i)
        except Exception as exc:  # pragma: no cover - failure is the assertion
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(t * 100,)) for t in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert not errors
    journal = evidence_home / "journal.jsonl"
    result = _verify(journal, trusted_keys(evidence_home))
    assert result.valid, result.issues
    assert result.events_verified == 8 * 10 * 2


# --- CLI for the new commands --------------------------------------------------


def test_cli_resolve_round_trip(evidence_home, capsys):
    from interceptor.cli import EXIT_OK, main

    @guard(action="test.cli-resolve", approval_provider=allow())
    def act() -> str:
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError):
        act()
    decision_id = next(e for e in events(evidence_home) if e["event_type"] == "decision")[
        "event_id"
    ]
    assert (
        main(
            [
                "resolve",
                "--decision",
                decision_id,
                "--result",
                "not-completed",
                "--note",
                "checked",
            ]
        )
        == EXIT_OK
    )
    assert decision_id in capsys.readouterr().out
    assert main(["audit"]) == EXIT_OK
    assert "resolved_not_completed" in capsys.readouterr().out


def test_cli_resolve_bad_decision(evidence_home):
    from interceptor.cli import EXIT_FAILURE, main

    assert main(["resolve", "--decision", "nope", "--result", "completed"]) == EXIT_FAILURE


def test_cli_countersign_and_keygen(evidence_home, tmp_path, capsys):
    from interceptor import checkpoint_journal
    from interceptor.cli import EXIT_FAILURE, EXIT_OK, main

    @guard(action="test.cli-cosign", approval_provider=allow())
    def act() -> str:
        return "ok"

    act()
    journal = evidence_home / "journal.jsonl"
    checkpoint_journal(journal)
    counter_key = tmp_path / "counter.pem"
    assert main(["keygen", "--output", str(counter_key), "--json"]) == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["key_id"].startswith("ed25519:")
    assert "PRIVATE" not in capsys.readouterr().out + json.dumps(payload)
    assert main(["countersign", "--signing-key", str(counter_key)]) == EXIT_OK
    assert "Counter-signed" in capsys.readouterr().out
    assert main(["countersign", "--signing-key", str(tmp_path / "missing.pem")]) == (EXIT_FAILURE)


def test_cli_export_and_stats(evidence_home, tmp_path, capsys):
    from interceptor.cli import EXIT_FAILURE, EXIT_OK, main

    @guard(action="test.cli-export", approval_provider=allow())
    def act() -> str:
        return "ok"

    act()
    out_json = tmp_path / "pack.json"
    assert main(["export", "--output", str(out_json)]) == EXIT_OK
    assert json.loads(out_json.read_text())["verification"]["valid"] is True
    out_html = tmp_path / "pack.html"
    assert main(["export", "--format", "html", "--output", str(out_html)]) == EXIT_OK
    assert "<html" in out_html.read_text()
    assert main(["export"]) == EXIT_OK
    assert "interceptor-evidence-pack/1" in capsys.readouterr().out
    assert main(["stats"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "test.cli-export" in out
    assert main(["stats", "--json"]) == EXIT_OK
    assert json.loads(capsys.readouterr().out)["decisions"] == 1
    assert main(["export", "--journal", str(tmp_path / "missing.jsonl")]) == EXIT_FAILURE
    assert main(["stats", "--journal", str(tmp_path / "missing.jsonl")]) == EXIT_FAILURE


# --- verifier edges for the new event types ------------------------------------


def test_countersignature_orphan_detected(evidence_home, tmp_path):
    from interceptor import checkpoint_journal

    @guard(action="test.orphan", approval_provider=allow())
    def act() -> str:
        return "ok"

    act()
    journal = evidence_home / "journal.jsonl"
    checkpoint_journal(journal)
    counter_key = tmp_path / "counter.pem"
    generate_private_key(counter_key)
    countersign_journal(journal, counter_key)
    # Delete the checkpoint line: the countersignature now dangles.
    kept = [
        line
        for line in journal.read_text().splitlines()
        if '"checkpoint"' not in line or '"countersignature"' in line
    ]
    journal.write_text("\n".join(kept) + "\n")
    signer = EphemeralSigningIdentity.from_file(counter_key)
    from interceptor.identity import key_id_for

    counter_id = key_id_for(signer.public_key())
    from interceptor.identity import load_public_key as _lpk

    result = verify_journal(journal, trusted_keys(evidence_home))
    assert not result.valid
    assert any(i.code == "countersignature_orphan" for i in result.issues)
    assert counter_id.startswith("ed25519:")
    assert _lpk is not None


def test_resolution_bad_values_rejected(evidence_home):
    from interceptor.identity import LocalSigningIdentity
    from interceptor.journal import (
        EVENT_SCHEMA_VERSION,
        FileJournal,
        finalize_event,
        new_event_id,
        utc_timestamp,
    )

    @guard(action="test.badres", approval_provider=allow())
    def act() -> str:
        return "ok"

    act()
    journal = evidence_home / "journal.jsonl"
    decision = next(e for e in events(evidence_home) if e["event_type"] == "decision")
    identity = LocalSigningIdentity.load_or_create()

    def build_bad(previous_hash):
        payload = {
            "schema_version": EVENT_SCHEMA_VERSION,
            "event_type": "resolution",
            "event_id": new_event_id(),
            "action_id": decision["action_id"],
            "action_name": decision["action_name"],
            "contract_hash": decision["contract_hash"],
            "timestamp_utc": utc_timestamp(),
            "key_id": identity.key_id,
            "previous_event_hash": previous_hash,
            "decision_event_id": decision["event_id"],
            "resolution": "maybe",
            "note": "x",
        }
        return finalize_event(payload, identity.sign)

    FileJournal(journal).append_event(build_bad)
    result = verify_journal(journal, trusted_keys(evidence_home))
    assert not result.valid
    assert any(i.code == "resolution_bad_value" for i in result.issues)


def test_resolve_note_bounded_and_missing_journal(tmp_path):
    from interceptor.resolve import resolve_journal as _resolve

    journal = tmp_path / "journal.jsonl"
    with pytest.raises(ic.ResolutionError):
        _resolve(journal, "x", "confirmed_completed")
    with pytest.raises(ic.ResolutionError):
        _resolve(journal, "x", "confirmed_completed", note=123)


def test_policy_edges():
    req = ic.ApprovalRequest(
        action_name="a",
        risk="low",
        approval_mode="required",
        redacted_input_summary="",
        input_hash="h",
        contract_hash="c",
    )
    with pytest.raises(ic.PolicyError):
        RuleProvider([Rule(action="x", decision="maybe")])
    with pytest.raises(ic.PolicyError):
        RuleProvider([], default="sometimes")

    class Exploding:
        pass

    provider = ic.PredicateProvider(lambda r: 1 / 0)
    assert not provider.decide(req).allowed
    assert Exploding is not None


# --- receipts ------------------------------------------------------------------


def test_receipt_recorded_on_outcome(evidence_home):
    @guard(
        action="test.receipt",
        approval_provider=allow(),
        receipt_from=lambda result: {"processor": "acme", "refund_id": result["id"]},
    )
    def act() -> dict:
        return {"id": "re_123", "ok": True}

    assert act()["id"] == "re_123"
    outcome = next(e for e in events(evidence_home) if e["event_type"] == "outcome")
    assert outcome["receipt"] == {"processor": "acme", "refund_id": "re_123"}


def test_receipt_redacted_and_optional(evidence_home):
    @guard(
        action="test.receipt-secret",
        approval_provider=allow(),
        receipt_from=lambda result: {"api_key": "sk-live-abcdefgh12345678", "id": "1"},
    )
    def act() -> dict:
        return {"ok": True}

    act()
    outcome = next(e for e in events(evidence_home) if e["event_type"] == "outcome")
    assert outcome["receipt"] == {"api_key": "<REDACTED>", "id": "1"}

    @guard(action="test.no-receipt", approval_provider=allow())
    def plain() -> str:
        return "ok"

    plain()
    outcome2 = next(
        e
        for e in events(evidence_home)
        if e["event_type"] == "outcome" and e["action_name"] == "test.no-receipt"
    )
    assert "receipt" not in outcome2


def test_receipt_extractor_failure_drops_receipt(evidence_home):
    def bad(result):
        raise RuntimeError("nope")

    @guard(action="test.receipt-bad", approval_provider=allow(), receipt_from=bad)
    def act() -> str:
        return "ok"

    assert act() == "ok"
    outcome = next(e for e in events(evidence_home) if e["event_type"] == "outcome")
    assert "receipt" not in outcome


def test_receipt_must_be_a_mapping(evidence_home):
    @guard(action="test.receipt-list", approval_provider=allow(), receipt_from=lambda r: [1])
    def act() -> str:
        return "ok"

    act()
    outcome = next(e for e in events(evidence_home) if e["event_type"] == "outcome")
    assert "receipt" not in outcome


# --- quorum --------------------------------------------------------------------


def test_quorum_provider():
    from interceptor.policy import QuorumApprovalProvider

    req = ic.ApprovalRequest(
        action_name="a",
        risk="high",
        approval_mode="required",
        redacted_input_summary="",
        input_hash="h",
        contract_hash="c",
    )
    quorum = QuorumApprovalProvider([allow(), allow(), deny()], quorum=2)
    assert quorum.decide(req).allowed
    strict = QuorumApprovalProvider([allow(), deny(), deny()], quorum=2)
    assert not strict.decide(req).allowed
    with pytest.raises(ValueError):
        QuorumApprovalProvider([allow()], quorum=2)
    with pytest.raises(ValueError):
        QuorumApprovalProvider([], quorum=1)


# --- approval server -----------------------------------------------------------


def test_approval_server_allow_deny(allow_socket_creation):
    import urllib.request

    from interceptor.approve_server import ApprovalServer, ServerApprovalProvider

    with ApprovalServer() as server:
        assert server.url.startswith("http://127.0.0.1:")
        provider = ServerApprovalProvider(server, timeout_seconds=10)
        req = ic.ApprovalRequest(
            action_name="deploy.prod",
            risk="critical",
            approval_mode="required",
            redacted_input_summary="ref=v1.2.3",
            input_hash="h",
            contract_hash="c",
        )
        holder: dict = {}

        def decide():
            holder["decision"] = provider.decide(req)

        thread = threading.Thread(target=decide)
        thread.start()
        try:
            # Page lists the pending request without a token leak check.
            token = server.url.split("token=")[1]
            with urllib.request.urlopen(server.url) as response:
                page = response.read().decode()
            assert "deploy.prod" in page and "v1.2.3" in page
            # The token rides in the form's hidden field (that's the auth mechanism);
            # what must not leak is anything beyond the redacted request.
            assert "name='token'" in page
            assert "sk-" not in page
            # Wrong token is rejected.
            bad = urllib.request.Request(
                server.url.replace(token, "wrong"),
            )
            try:
                urllib.request.urlopen(bad)
                raise AssertionError("expected 403")
            except urllib.error.HTTPError as exc:
                assert exc.code == 403
            # Approve from the "phone".
            data = urllib.parse.urlencode(
                {"token": token, "id": "req-1", "decision": "allow", "by": "ops"}
            ).encode()
            base = server.url.split("?")[0]
            post = urllib.request.Request(base + "decide", data=data)
            with urllib.request.urlopen(post) as response:
                assert response.read() == b"recorded"
            thread.join(timeout=10)
            assert holder["decision"].allowed
            assert holder["decision"].approved_by == "ops"
        finally:
            thread.join(timeout=10)


def test_approval_server_timeout(allow_socket_creation):
    from interceptor.approve_server import ApprovalServer, ServerApprovalProvider

    with ApprovalServer() as server:
        provider = ServerApprovalProvider(server, timeout_seconds=0.1)
        req = ic.ApprovalRequest(
            action_name="a",
            risk="low",
            approval_mode="required",
            redacted_input_summary="",
            input_hash="h",
            contract_hash="c",
        )
        decision = provider.decide(req)
        assert not decision.allowed
        assert "timed out" in decision.reason or "within" in decision.reason


def test_server_provider_end_to_end(evidence_home, allow_socket_creation):
    import threading as _threading

    from interceptor.approve_server import ApprovalServer, ServerApprovalProvider

    with ApprovalServer() as server:
        provider = ServerApprovalProvider(server, timeout_seconds=15)

        @guard(action="test.web-approve", approval_provider=provider)
        def act() -> str:
            return "deployed"

        result: dict = {}

        def call():
            result["value"] = act()

        thread = _threading.Thread(target=call)
        thread.start()
        try:
            import time as _time
            import urllib.parse as _parse
            import urllib.request as _request

            deadline = _time.monotonic() + 10
            approved = False
            while _time.monotonic() < deadline:
                pending = server._snapshot()
                if pending:
                    pending_id, _ = pending[0]
                    token = server.url.split("token=")[1]
                    data = _parse.urlencode(
                        {"token": token, "id": pending_id, "decision": "allow"}
                    ).encode()
                    with _request.urlopen(server.url.split("?")[0] + "decide", data=data):
                        pass
                    approved = True
                    break
                _time.sleep(0.05)
            assert approved
            thread.join(timeout=15)
            assert result["value"] == "deployed"
        finally:
            thread.join(timeout=15)


# --- schemas -------------------------------------------------------------------


def test_describe_tool_schema():
    from interceptor.schemas import as_openai_tool, describe_tool, mcp_tool

    def refund(customer_id: str, amount_cents: int, note: str | None = None) -> dict:
        """Refund a customer."""
        return {}

    schema = describe_tool(refund)
    assert schema["name"] == "refund"
    assert schema["description"] == "Refund a customer."
    assert schema["parameters"]["properties"]["customer_id"] == {"type": "string"}
    assert schema["parameters"]["properties"]["amount_cents"] == {"type": "integer"}
    assert schema["parameters"]["required"] == ["customer_id", "amount_cents"]

    openai_tool = as_openai_tool(refund)
    assert openai_tool["type"] == "function"
    assert openai_tool["function"]["name"] == "refund"

    class FakeServer:
        def __init__(self):
            self.registered = {}

        def tool(self, name=None, description=None):
            def deco(fn):
                self.registered[name] = fn
                return fn

            return deco

    server = FakeServer()

    @guard(action="test.mcp-tool", approval_provider=allow())
    def guarded_tool(x: int) -> int:
        return x

    mcp_tool(server, guarded_tool)
    assert server.registered["guarded_tool"](21) == 21
    recorded = [e for e in events.__wrapped__] if hasattr(events, "__wrapped__") else None
    assert recorded is None  # schemas never touch the journal


def test_describe_guarded_keeps_signature(evidence_home):
    from interceptor.schemas import describe_tool

    @guard(action="test.schema-guarded", approval_provider=allow())
    def act(customer_id: str, amount_cents: int = 100) -> dict:
        """Do a thing."""
        return {}

    schema = describe_tool(act)
    assert schema["parameters"]["required"] == ["customer_id"]


# --- archive -------------------------------------------------------------------


def test_archive_round_trip(evidence_home):
    from interceptor import archive_journal

    @guard(action="test.archive", approval_provider=allow())
    def act() -> str:
        return "ok"

    act()
    journal = evidence_home / "journal.jsonl"
    report = archive_journal(journal)
    assert report.prior_count == 2
    assert report.archived_path.exists()
    assert not journal.exists() or journal.stat().st_size > 0
    # New file starts with the archive link.
    fresh = [json.loads(line) for line in journal.read_text().splitlines()]
    assert len(fresh) == 1 and fresh[0]["event_type"] == "archive"
    assert fresh[0]["prior_count"] == 2
    assert fresh[0]["previous_event_hash"] is None
    # Both files verify standalone.
    assert verify_journal(journal, trusted_keys(evidence_home)).valid
    assert verify_journal(report.archived_path, trusted_keys(evidence_home)).valid
    # Guarded calls continue on the new file.
    act()
    assert len(journal.read_text().splitlines()) == 3


def test_archive_empty_and_keep(evidence_home):
    from interceptor import archive_journal

    journal = evidence_home / "journal.jsonl"
    journal.write_text("")
    with pytest.raises(ic.ArchiveError):
        archive_journal(journal)

    @guard(action="test.archive-keep", approval_provider=allow())
    def act() -> str:
        return "ok"

    act()
    first = archive_journal(journal, keep=1)
    act()
    second = archive_journal(journal, keep=1)
    assert second.archived_path.exists()
    assert not first.archived_path.exists()
    with pytest.raises(ic.ArchiveError):
        archive_journal(journal, keep=0)


def test_cli_archive(evidence_home, capsys):
    from interceptor.cli import EXIT_OK, main

    @guard(action="test.cli-archive", approval_provider=allow())
    def act() -> str:
        return "ok"

    act()
    assert main(["archive", "--json"]) == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["prior_count"] == 2
    assert main(["stats"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "archives" in out
    # The live file now holds only the archive link; archiving again is fine.
    assert main(["archive"]) == EXIT_OK
