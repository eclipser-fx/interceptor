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


def test_unknown_command_is_a_usage_error(capsys):
    with pytest.raises(SystemExit) as caught:
        main(["nonsense"])
    assert caught.value.code == 2
