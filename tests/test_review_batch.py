"""Regression tests for the engineering-review batch.

Each test pins one reviewed finding: fail-open composition, exit codes,
privacy scope, ship-failure semantics, resolution unblocking, strict inputs.
"""

from __future__ import annotations

import json

import pytest

from helpers import allow, deny
from interceptor import (
    FileBudgetProvider,
    guard,
    inspect_journal,
    load_policy_file,
    resolve_journal,
    verify_journal,
    wrap_tool,
    wrap_tools,
)
from interceptor.approval import ApprovalDecision, ApprovalRequest
from interceptor.errors import (
    ActionDenied,
    ApprovalError,
    ContractError,
    DuplicateActionError,
    EventShipError,
    EvidenceAuditError,
    PolicyError,
    ToolWrapError,
)
from interceptor.identity import load_trusted_public_keys
from interceptor.journal import FileJournal
from interceptor.shipping import FanoutJournalStore


def _req() -> ApprovalRequest:
    return ApprovalRequest("a.act", "low", "required", "", "h", "c")


def test_never_with_provider_is_a_decoration_time_error():
    with pytest.raises(ContractError):

        @guard(action="x.never", approval="never", approval_provider=allow())
        def act() -> None:
            return None

    def raw() -> None:
        return None

    with pytest.raises(ToolWrapError):
        wrap_tool(raw, action="x.never", approval="never", approval_provider=allow())


def test_provider_denial_matching_duplicate_text_stays_denied(evidence_home, tmp_path):
    journal = tmp_path / "j.jsonl"

    class EchoDeny:
        def decide(self, request) -> ApprovalDecision:
            return ApprovalDecision(
                "denied", "duplicate idempotency key; already reserved or completed"
            )

    @guard(
        action="x.echo",
        journal=journal,
        approval_provider=EchoDeny(),
        idempotency_key="k",
    )
    def act(k: str) -> str:
        return k

    with pytest.raises(ActionDenied) as exc_info:
        act("K-1")
    assert not isinstance(exc_info.value, DuplicateActionError)


def test_export_output_exit_code_reflects_validity(evidence_home, tmp_path, capsys):
    from interceptor.cli import EXIT_FAILURE, EXIT_OK, main

    journal = evidence_home / "journal.jsonl"

    @guard(action="x.ok", journal=journal, approval_provider=allow())
    def act(x: int) -> int:
        return x

    act(1)
    out = tmp_path / "pack.json"
    assert main(["export", "--journal", str(journal), "--output", str(out)]) == EXIT_OK
    lines = journal.read_text().splitlines()
    event = json.loads(lines[0])
    event["risk"] = "low"
    lines[0] = json.dumps(event, sort_keys=True, separators=(",", ":"))
    journal.write_text("\n".join(lines) + "\n")
    capsys.readouterr()
    assert main(["export", "--journal", str(journal), "--output", str(out)]) == EXIT_FAILURE


def test_export_html_json_conflict_is_usage_error(capsys):
    from interceptor.cli import main

    with pytest.raises(SystemExit) as exc_info:
        main(["export", "--format", "html", "--json"])
    assert exc_info.value.code == 2


def test_archive_keep_rejects_non_positive(capsys):
    from interceptor.cli import main

    with pytest.raises(SystemExit) as exc_info:
        main(["archive", "--keep", "0"])
    assert exc_info.value.code == 2
    with pytest.raises(SystemExit) as exc_info:
        main(["archive", "--keep", "-3"])
    assert exc_info.value.code == 2


def test_inspect_flags_receipts_and_error_summaries(evidence_home):
    journal = evidence_home / "journal.jsonl"

    @guard(
        action="billing.refund",
        journal=journal,
        approval_provider=allow(),
        receipt_from=lambda r: {"processor": "acme", "refund_id": r["id"]},
    )
    def refund(which: str) -> dict:
        if which == "boom":
            raise ValueError("processor exploded")
        return {"id": which}

    refund("re_1")
    with pytest.raises(ValueError):
        refund("boom")
    report = inspect_journal(journal)
    assert report.safe_for_upload is False
    assert len(report.disclosing_outcome_event_ids) == 2


def test_inspect_clean_journal_stays_safe(evidence_home):
    journal = evidence_home / "journal.jsonl"

    @guard(action="x.safe", journal=journal, approval_provider=allow(), redact=["pin"])
    def act(pin: str) -> None:
        return None

    act("1234")
    report = inspect_journal(journal)
    assert report.safe_for_upload is True
    assert report.disclosing_outcome_event_ids == ()


def test_inspect_accepts_repeated_public_keys(evidence_home, tmp_path):
    from interceptor.identity import LocalSigningIdentity, rotate_key

    journal = evidence_home / "journal.jsonl"

    @guard(action="x.keyed", journal=journal, approval_provider=allow())
    def act(x: int) -> int:
        return x

    act(1)
    from cryptography.hazmat.primitives import serialization

    old_pem = tmp_path / "old.pem"
    old_pem.write_bytes(
        LocalSigningIdentity.load_or_create()
        .public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    rotate_key()
    new = LocalSigningIdentity.load_or_create().public_key_path
    report = inspect_journal(journal, public_key_path=[old_pem, new])
    assert report.decision_count == 1


def test_ship_failure_on_outcome_carries_result(evidence_home, tmp_path):
    journal = tmp_path / "j.jsonl"

    def boom(event):
        if event.get("event_type") == "outcome":
            raise RuntimeError("mirror down")

    store = FanoutJournalStore(FileJournal(journal), [boom])

    @guard(action="x.ship", journal=store, approval_provider=allow())
    def act(x: int) -> int:
        return x * 2

    with pytest.raises(EventShipError) as exc_info:
        act(21)
    assert exc_info.value.result == 42
    assert exc_info.value.decision_event_id is not None
    # The local outcome is durable despite the witness failure.
    keys = load_trusted_public_keys(evidence_home)
    assert verify_journal(journal, keys).valid


def test_resolution_not_completed_unblocks_key(evidence_home, tmp_path):
    journal = tmp_path / "j.jsonl"
    calls: list[str] = []

    @guard(
        action="x.res",
        journal=journal,
        approval_provider=allow(),
        idempotency_key="k",
    )
    def act(k: str) -> str:
        calls.append(k)
        raise KeyboardInterrupt("killed before outcome persisted")

    with pytest.raises(KeyboardInterrupt):
        act("K-9")
    # No outcome was recorded; the key reads in-progress and blocks...
    with pytest.raises(DuplicateActionError):
        act("K-9")
    decision = next(
        json.loads(line)
        for line in journal.read_text().splitlines()
        if json.loads(line)["event_type"] == "decision"
    )
    resolve_journal(
        journal, decision["event_id"], "confirmed_not_completed", note="checked: absent"
    )
    with pytest.raises(KeyboardInterrupt):
        act("K-9")
    assert calls == ["K-9", "K-9"]


def test_none_idempotency_key_is_contract_error(tmp_path):
    journal = tmp_path / "j.jsonl"

    @guard(
        action="x.none",
        journal=journal,
        approval_provider=allow(),
        idempotency_key=lambda bound: None,
    )
    def act(k: str) -> str:
        return k

    with pytest.raises(ContractError):
        act("K-1")


def test_malformed_provider_return_is_approval_error(evidence_home, tmp_path):
    journal = tmp_path / "j.jsonl"

    class NullProvider:
        def decide(self, request):
            return None

    @guard(action="x.null", journal=journal, approval_provider=NullProvider())
    def act() -> None:
        return None

    with pytest.raises(ApprovalError):
        act()


def test_policy_file_rejects_unknown_keys_and_risks(tmp_path):
    bad_keys = tmp_path / "keys.json"
    bad_keys.write_text(
        json.dumps({"rules": [{"action": "a.*", "decision": "allowed", "decison": "x"}]})
    )
    with pytest.raises(PolicyError):
        load_policy_file(bad_keys)
    bad_risks = tmp_path / "risks.json"
    bad_risks.write_text(
        json.dumps({"rules": [{"action": "a.*", "decision": "allowed", "risks": ["bogus"]}]})
    )
    with pytest.raises(PolicyError):
        load_policy_file(bad_risks)
    bad_top = tmp_path / "top.json"
    bad_top.write_text(json.dumps({"default": "denied", "rules": [], "extra": 1}))
    with pytest.raises(PolicyError):
        load_policy_file(bad_top)
    good = tmp_path / "good.json"
    good.write_text(
        json.dumps(
            {
                "default": "denied",
                "rules": [
                    {"action": "a.*", "decision": "allowed", "risks": ["low"], "reason": "ok"}
                ],
            }
        )
    )
    provider = load_policy_file(good)
    assert provider.decide(_req()).allowed


def test_wrap_tools_translates_bad_action_and_rejects_defaults():
    def raw() -> None:
        return None

    with pytest.raises(ToolWrapError):
        wrap_tools({"t": raw}, configuration={"t": {"action": "bad name!"}})
    with pytest.raises(ToolWrapError):
        wrap_tools(
            {"t": raw},
            configuration={"t": {"action": "ok.name"}},
            approval_provider=allow(),
        )


def test_short_secrets_do_not_mangle_error_text_but_still_suppress_hashes():
    from interceptor.redaction import scrub_text

    assert scrub_text("y-axis and x", ["y", "x", "long-secret-value"]) == (
        "y-axis and x".replace("long-secret-value", "<REDACTED>")
    )
    assert "long-secret-value" not in scrub_text(
        "saw long-secret-value here", ["long-secret-value"]
    )


def test_render_html_rejects_malformed_bundle():
    from interceptor import render_html

    with pytest.raises(EvidenceAuditError):
        render_html({"journal": "x"})
    pack = {
        "journal": "j",
        "exported_at": "t",
        "verification": {"valid": True, "events_verified": 0, "issues": []},
        "audit": {"invocations": [], "issues": []},
    }
    assert "<title>Evidence pack</title>" in render_html(pack)


def test_archived_path_dot_segments_rejected(evidence_home, tmp_path):
    from interceptor import checkpoint_journal

    journal = evidence_home / "journal.jsonl"

    @guard(action="x.dot", journal=journal, approval_provider=allow())
    def act() -> None:
        return None

    act()
    checkpoint_journal(journal)
    lines = journal.read_text().splitlines()
    lines.append(
        json.dumps(
            {
                "schema_version": "1",
                "event_type": "archive",
                "event_id": "00000000-0000-4000-8000-000000000099",
                "timestamp_utc": "2026-01-01T00:00:00.000000Z",
                "key_id": "ed25519:0000000000000000",
                "previous_event_hash": "x",
                "event_hash": "y",
                "signature": "e30=",
                "prior_count": 1,
                "prior_head": "x",
                "archived_path": "..",
            }
        )
    )
    journal.write_text("\n".join(lines) + "\n")
    result = verify_journal(journal, load_trusted_public_keys(evidence_home))
    assert not result.valid
    assert any(issue.code == "archive_bad_path" for issue in result.issues)


def test_resolve_note_truncation_marked(evidence_home, tmp_path):
    from interceptor import resolve_journal as resolve

    journal = tmp_path / "j.jsonl"

    @guard(action="x.note", journal=journal, approval_provider=allow())
    def act() -> None:
        raise ValueError("nope")

    with pytest.raises(ValueError):
        act()
    decision = next(
        json.loads(line)
        for line in journal.read_text().splitlines()
        if json.loads(line)["event_type"] == "decision"
    )
    report = resolve(journal, decision["event_id"], "confirmed_not_completed", note="n" * 2000)
    assert report.resolution_event["note"].endswith("…")
    assert len(report.resolution_event["note"]) == 1000


def test_precheck_cache_tracks_appends(tmp_path):
    from interceptor.journal import (
        find_blocking_idempotent_decision,
        find_completed_idempotent_decision,
        reset_precheck_cache,
    )

    journal = tmp_path / "j.jsonl"

    @guard(action="x.cache", journal=journal, approval_provider=allow(), idempotency_key="k")
    def act(k: str) -> str:
        return k

    # Miss, then hit: same answer without rescanning.
    assert find_blocking_idempotent_decision(journal, "x.cache", "K-1") is None
    assert find_blocking_idempotent_decision(journal, "x.cache", "K-1") is None
    act("K-1")
    # The append invalidated the cache: the blocker is now visible...
    first = find_blocking_idempotent_decision(journal, "x.cache", "K-1")
    assert first is not None
    # ...and stable across cache hits.
    second = find_blocking_idempotent_decision(journal, "x.cache", "K-1")
    assert second is not None and second["event_id"] == first["event_id"]
    assert find_completed_idempotent_decision(journal, "x.cache", "K-1") is not None
    reset_precheck_cache()
    assert find_blocking_idempotent_decision(journal, "x.cache", "K-1") is not None


def test_file_budget_survives_concurrent_decides(tmp_path):
    import threading

    state = tmp_path / "budget.json"
    provider = FileBudgetProvider(50, state)
    allowed = 0
    lock = threading.Lock()

    def worker():
        nonlocal allowed
        for _ in range(10):
            if provider.decide(_req()).allowed:
                with lock:
                    allowed += 1

    threads = [threading.Thread(target=worker) for _ in range(10)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert allowed == 50


def test_deny_provider_keeps_working_with_never_budgets():
    assert not deny().decide(_req()).allowed
