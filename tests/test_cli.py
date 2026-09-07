"""The CLI is the offline check, so its exit codes are part of the contract."""

from __future__ import annotations

import json

import pytest

from helpers import allow
from interceptor import guard
from interceptor.cli import EXIT_FAILURE, EXIT_OK, main


def record(action: str = "cli.test", **kwargs) -> None:
    @guard(action=action, approval_provider=allow(), **kwargs)
    def act(amount: int, api_key: str = "sk-CLI-SECRET") -> int:
        return amount

    act(1)


def test_verify_succeeds_on_a_clean_journal(evidence_home, capsys):
    record()
    assert main(["verify"]) == EXIT_OK
    out = capsys.readouterr().out
    assert out.startswith("OK")
    assert "truncation" in out, "the tail-truncation limit must be surfaced, not buried"


def test_verify_json_output_is_parseable(evidence_home, capsys):
    record()
    assert main(["verify", "--json"]) == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["valid"] is True
    assert payload["events_verified"] == 2
    assert payload["issues"] == []


def test_verify_fails_on_a_tampered_journal(evidence_home, capsys):
    record()
    path = evidence_home / "journal.jsonl"
    lines = path.read_text().splitlines()
    event = json.loads(lines[0])
    event["risk"] = "low"
    lines[0] = json.dumps(event, sort_keys=True, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n")

    assert main(["verify"]) == EXIT_FAILURE
    assert "FAIL" in capsys.readouterr().out


def test_verify_reports_a_missing_journal(evidence_home, capsys):
    assert main(["verify"]) == EXIT_FAILURE
    assert "no journal" in capsys.readouterr().err


def test_key_info_never_prints_private_material(evidence_home, capsys):
    assert main(["key-info"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "ed25519:" in out
    assert "PRIVATE KEY" not in out

    private = (evidence_home / "signing_key.pem").read_text()
    for line in private.splitlines():
        if len(line) > 20 and "-----" not in line:
            assert line not in out


def test_inspect_flags_arguments_recorded_in_the_clear(evidence_home, capsys):
    record()
    assert main(["inspect"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "cli.test" in out
    assert "amount" in out, "a non-sensitive argument is retained and should be reported"
    assert "sk-CLI-SECRET" not in out


def test_inspect_json_output_is_parseable(evidence_home, capsys):
    record()
    assert main(["inspect", "--json"]) == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["event_count"] == 2
    assert payload["actions"][0]["action_name"] == "cli.test"


def test_audit_reports_completed_invocation(evidence_home, capsys):
    record()
    assert main(["audit", "--json"]) == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["structurally_valid"] is True
    assert payload["needs_reconciliation"] is False
    assert payload["counts"]["succeeded"] == 1
    assert payload["invocations"][0]["action_name"] == "cli.test"


def test_audit_fails_gate_for_incomplete_invocation(evidence_home, capsys):
    record()
    path = evidence_home / "journal.jsonl"
    path.write_text(path.read_text().splitlines()[0] + "\n")

    assert main(["audit"]) == EXIT_FAILURE
    out = capsys.readouterr().out
    assert "needs_reconciliation" in out
    assert "before retrying" in out


def test_audit_status_filter_is_display_only(evidence_home, capsys):
    record()
    # Filtering to a non-matching status shows nothing but still exits OK:
    # the gate reflects the full journal, never the filtered view.
    assert main(["audit", "--json", "--status", "failed"]) == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["counts"]["succeeded"] == 1
    assert payload["invocations"] == []
    assert payload["filter"]["statuses"] == ["failed"]
    assert payload["filter"]["total"] == 1


def test_audit_limit_truncates_display_only(evidence_home, capsys):
    record()
    record(action="cli.second")
    assert main(["audit", "--json", "--limit", "1"]) == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["counts"]["succeeded"] == 2
    assert len(payload["invocations"]) == 1
    assert payload["filter"]["truncated"] is True

    assert main(["audit", "--limit", "1"]) == EXIT_OK
    assert "showing 1 of 2" in capsys.readouterr().out


def test_audit_filter_never_masks_reconciliation(evidence_home, capsys):
    record()
    path = evidence_home / "journal.jsonl"
    path.write_text(path.read_text().splitlines()[0] + "\n")

    # Even filtered to a clean status, the exit code reflects the full journal.
    assert main(["audit", "--status", "succeeded"]) == EXIT_FAILURE
    capsys.readouterr()
    assert main(["audit", "--status", "succeeded", "--json"]) == EXIT_FAILURE
    payload = json.loads(capsys.readouterr().out)
    assert payload["needs_reconciliation"] is True


def test_verify_warns_on_stale_covering_witness(evidence_home, tmp_path, capsys):
    import os
    import time

    from interceptor import witness_journal

    record()
    journal = evidence_home / "journal.jsonl"
    witness_dir = tmp_path / "witness"
    report = witness_journal(journal, witness_dir)
    old = time.time() - 3600
    os.utime(report.shipped_path, (old, old))

    assert main(["verify", "--checkpoint", str(report.shipped_path)]) == EXIT_OK
    assert "witness age" in capsys.readouterr().out

    assert (
        main(
            [
                "verify",
                "--checkpoint",
                str(report.shipped_path),
                "--witness-max-age",
                "300",
            ]
        )
        == EXIT_OK
    )
    out = capsys.readouterr().out
    assert "WARNING" in out
    assert "stale" in out

    assert (
        main(
            [
                "verify",
                "--checkpoint",
                str(report.shipped_path),
                "--witness-max-age",
                "7200",
                "--json",
            ]
        )
        == EXIT_OK
    )
    import json as _json

    payload = _json.loads(capsys.readouterr().out)
    assert payload["witness_stale_warning"] is False
    assert payload["witness_age_seconds"] is not None and payload["witness_age_seconds"] > 3000


def test_audit_max_events_refuses_oversized_journal(evidence_home, capsys):
    from interceptor.errors import EvidenceAuditError

    record()
    record(action="cli.second")
    with pytest.raises(EvidenceAuditError, match="max-events"):
        from interceptor import audit_journal_streaming
        from interceptor.identity import load_trusted_public_keys

        audit_journal_streaming(
            evidence_home / "journal.jsonl",
            load_trusted_public_keys(evidence_home),
            max_events=1,
        )
    assert main(["audit", "--max-events", "1"]) == EXIT_FAILURE
    assert "max-events" in capsys.readouterr().err
    assert main(["audit", "--max-events", "100"]) == EXIT_OK


def test_unknown_command_is_a_usage_error(capsys):
    with pytest.raises(SystemExit) as caught:
        main(["nonsense"])
    assert caught.value.code == 2
