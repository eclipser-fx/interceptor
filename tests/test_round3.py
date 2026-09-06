"""Round 3: external signers, encrypted keys, spend budgets, attested approval, gateway."""

from __future__ import annotations

import json

import pytest

from helpers import allow, deny
from interceptor import (
    AttestedApprovalProvider,
    CallbackSigningIdentity,
    FileSpendingBudgetProvider,
    SpendingBudgetProvider,
    ToolGateway,
    generate_private_key,
    guard,
    load_private_key,
    rotate_key,
    verify_journal,
    wrap_tool,
)
from interceptor.approval import ApprovalRequest
from interceptor.errors import (
    ActionDenied,
    ContractError,
    IdentityError,
    SigningError,
    ToolWrapError,
)
from interceptor.identity import (
    EphemeralSigningIdentity,
    LocalSigningIdentity,
    load_trusted_public_keys,
)


def _req(spend=None, action="spend.act") -> ApprovalRequest:
    return ApprovalRequest(action, "high", "required", "", "h", "c", spend_cents=spend)


# --- external signers --------------------------------------------------------


def test_callback_identity_guards_and_verifies(tmp_path, monkeypatch):
    home = tmp_path / "home"
    monkeypatch.setenv("INTERCEPTOR_EVIDENCE_HOME", str(home))
    real = LocalSigningIdentity.load_or_create()
    journal = home / "journal.jsonl"

    def remote_sign(digest: bytes) -> str:
        return real.sign(digest)

    ext = CallbackSigningIdentity(real.public_key(), remote_sign)
    assert ext.key_id == real.key_id

    @guard(action="ext.act", journal=journal, approval_provider=allow(), identity=ext)
    def act(x: int) -> int:
        return x

    assert act(1) == 1
    assert verify_journal(journal, load_trusted_public_keys(home)).valid


def test_callback_identity_sign_failure_fails_closed(tmp_path, monkeypatch):
    home = tmp_path / "home"
    monkeypatch.setenv("INTERCEPTOR_EVIDENCE_HOME", str(home))
    real = LocalSigningIdentity.load_or_create()
    journal = home / "journal.jsonl"

    def broken(digest: bytes) -> str:
        raise RuntimeError("hsm session lost")

    ext = CallbackSigningIdentity(real.public_key(), broken)

    @guard(action="ext.act", journal=journal, approval_provider=allow(), identity=ext)
    def act(x: int) -> int:
        return x

    with pytest.raises(SigningError):
        act(1)


def test_callback_identity_rejects_non_string_signature(tmp_path, monkeypatch):
    home = tmp_path / "home"
    monkeypatch.setenv("INTERCEPTOR_EVIDENCE_HOME", str(home))
    real = LocalSigningIdentity.load_or_create()
    ext = CallbackSigningIdentity(real.public_key(), lambda digest: 42)
    with pytest.raises(SigningError):
        ext.sign(b"\x00" * 32)


def test_encrypted_key_roundtrip(tmp_path):
    path = tmp_path / "enc.pem"
    first = generate_private_key(path, "s3cret")
    assert path.exists()
    loaded = load_private_key(path, "s3cret")
    assert loaded.public_key().public_bytes_raw() == first.public_key().public_bytes_raw()
    back = EphemeralSigningIdentity.from_file(path, "s3cret")
    assert back.fingerprint == EphemeralSigningIdentity(first).fingerprint
    with pytest.raises(IdentityError):
        load_private_key(path, "wrong")
    with pytest.raises(IdentityError):
        load_private_key(path)
    with pytest.raises(IdentityError):
        generate_private_key(path, "other")
    with pytest.raises(IdentityError):
        generate_private_key(tmp_path / "empty-pw.pem", "")


def test_rotate_with_provisioned_successor(evidence_home):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from interceptor.identity import key_id_for, load_trusted_public_keys

    journal = evidence_home / "journal.jsonl"

    @guard(action="rot.prov", journal=journal, approval_provider=allow())
    def act(x: int) -> int:
        return x

    act(1)
    successor = Ed25519PrivateKey.generate()
    new_identity = rotate_key(journal_path=journal, new_key=successor)
    assert new_identity.key_id == key_id_for(successor.public_key())
    act(2)
    assert verify_journal(journal, load_trusted_public_keys(evidence_home)).valid


def test_keygen_and_countersign_with_password_env(tmp_path, monkeypatch, evidence_home):
    from interceptor import checkpoint_journal
    from interceptor.cli import EXIT_OK, main

    journal = evidence_home / "journal.jsonl"

    @guard(action="pw.act", journal=journal, approval_provider=allow())
    def act(x: int) -> int:
        return x

    act(1)
    checkpoint_journal(journal)
    counter = tmp_path / "counter.pem"
    monkeypatch.setenv("INTERCEPTOR_COUNTER_PW", "hunter3")
    assert (
        main(["keygen", "--output", str(counter), "--password-env", "INTERCEPTOR_COUNTER_PW"])
        == EXIT_OK
    )
    assert (
        main(
            [
                "countersign",
                "--journal",
                str(journal),
                "--signing-key",
                str(counter),
                "--password-env",
                "INTERCEPTOR_COUNTER_PW",
            ]
        )
        == EXIT_OK
    )
    kinds = [json.loads(line)["event_type"] for line in journal.read_text().splitlines()]
    assert "countersignature" in kinds


def test_countersign_missing_password_env_fails(tmp_path, evidence_home, capsys):
    from interceptor import checkpoint_journal
    from interceptor.cli import EXIT_FAILURE, main

    journal = evidence_home / "journal.jsonl"

    @guard(action="pw.act", journal=journal, approval_provider=allow())
    def act(x: int) -> int:
        return x

    act(1)
    checkpoint_journal(journal)
    from interceptor.cli import EXIT_OK

    assert main(["keygen", "--output", str(tmp_path / "c.pem")]) == EXIT_OK
    capsys.readouterr()
    # Flag given with an unset var: fail closed without touching the key.
    assert (
        main(
            [
                "countersign",
                "--journal",
                str(journal),
                "--signing-key",
                str(tmp_path / "c.pem"),
                "--password-env",
                "INTERCEPTOR_DEFINITELY_UNSET",
            ]
        )
        == EXIT_FAILURE
    )


# --- spend -------------------------------------------------------------------


def test_spend_recorded_on_decision(evidence_home):
    journal = evidence_home / "journal.jsonl"

    @guard(
        action="spend.act",
        journal=journal,
        approval_provider=allow(),
        spend_from=lambda bound: bound["amount_cents"],
    )
    def refund(amount_cents: int) -> int:
        return amount_cents

    refund(250)
    decision = json.loads(journal.read_text().splitlines()[0])
    assert decision["spend_cents"] == 250


def test_spend_absent_without_extractor(evidence_home):
    journal = evidence_home / "journal.jsonl"

    @guard(action="spend.act", journal=journal, approval_provider=allow())
    def act(x: int) -> int:
        return x

    act(1)
    assert "spend_cents" not in json.loads(journal.read_text().splitlines()[0])


def test_spend_extractor_failures_fail_closed(evidence_home):
    journal = evidence_home / "journal.jsonl"

    def boom(bound):
        raise RuntimeError("nope")

    @guard(action="spend.act", journal=journal, approval_provider=allow(), spend_from=boom)
    def act(x: int) -> int:
        return x

    with pytest.raises(ContractError):
        act(1)

    @guard(
        action="spend.bad",
        journal=journal,
        approval_provider=allow(),
        spend_from=lambda bound: "lots",
    )
    def act2(x: int) -> int:
        return x

    with pytest.raises(ContractError):
        act2(1)

    @guard(
        action="spend.neg",
        journal=journal,
        approval_provider=allow(),
        spend_from=lambda bound: -5,
    )
    def act3(x: int) -> int:
        return x

    with pytest.raises(ContractError):
        act3(1)


def test_wrap_tool_spend_from(tmp_path):
    journal = tmp_path / "j.jsonl"

    def refund(amount_cents: int) -> int:
        return amount_cents

    wrapped = wrap_tool(
        refund,
        action="wrap.spend",
        journal=journal,
        approval_provider=allow(),
        spend_from=lambda bound: bound["amount_cents"],
    )
    wrapped(99)
    assert json.loads(journal.read_text().splitlines()[0])["spend_cents"] == 99


def test_spending_budget_memory():
    provider = SpendingBudgetProvider(300)
    assert provider.decide(_req(100)).allowed
    assert provider.decide(_req(200)).allowed
    denied = provider.decide(_req(1))
    assert not denied.allowed
    assert not SpendingBudgetProvider(100).decide(_req(None)).allowed
    with pytest.raises(ValueError):
        SpendingBudgetProvider(-1)


def test_spending_budget_per_action():
    provider = SpendingBudgetProvider(100, per_action=True)
    assert provider.decide(_req(100, "a.one")).allowed
    assert not provider.decide(_req(1, "a.one")).allowed
    assert provider.decide(_req(100, "a.two")).allowed


def test_file_spending_budget_restart_and_corrupt(tmp_path):
    state = tmp_path / "spend.json"
    first = FileSpendingBudgetProvider(300, state)
    assert first.decide(_req(150)).allowed
    second = FileSpendingBudgetProvider(300, state)
    assert second.decide(_req(150)).allowed
    assert not second.decide(_req(1)).allowed
    with pytest.raises(ValueError):
        FileSpendingBudgetProvider(-1, state)
    state.write_text("{bad")
    assert not FileSpendingBudgetProvider(10**9, state).decide(_req(1)).allowed


def test_spend_budget_guards_real_call(evidence_home):
    from interceptor.policy import AllOf

    journal = evidence_home / "journal.jsonl"
    policy = AllOf([SpendingBudgetProvider(100), allow()])

    @guard(
        action="spend.cap",
        journal=journal,
        approval_provider=policy,
        spend_from=lambda bound: bound["amount_cents"],
    )
    def refund(amount_cents: int) -> int:
        return amount_cents

    refund(60)
    with pytest.raises(ActionDenied):
        refund(60)


# --- attested approval -------------------------------------------------------


def test_attested_stamps_allowed_and_passes_denied(monkeypatch):
    monkeypatch.delenv("INTERCEPTOR_APPROVER", raising=False)
    provider = AttestedApprovalProvider(allow(), approved_by="oncall:ana")
    decision = provider.decide(_req())
    assert decision.allowed and decision.approved_by == "oncall:ana"
    assert not AttestedApprovalProvider(deny(), approved_by="x").decide(_req()).allowed


def test_attested_reads_env_and_rejects_missing_or_malformed(monkeypatch):
    monkeypatch.setenv("INTERCEPTOR_APPROVER", "ops:bob")
    assert AttestedApprovalProvider(allow()).decide(_req()).approved_by == "ops:bob"
    monkeypatch.delenv("INTERCEPTOR_APPROVER", raising=False)
    assert not AttestedApprovalProvider(allow()).decide(_req()).allowed
    monkeypatch.setenv("INTERCEPTOR_APPROVER", "  Jane   Doe  ")
    assert AttestedApprovalProvider(allow()).decide(_req()).approved_by == "Jane Doe"
    monkeypatch.setenv("INTERCEPTOR_APPROVER", "has\ttab")
    assert AttestedApprovalProvider(allow()).decide(_req()).approved_by == "has tab"
    assert not AttestedApprovalProvider(allow(), approved_by="x" * 121).decide(_req()).allowed
    assert not AttestedApprovalProvider(allow(), approved_by="bad\x01id").decide(_req()).allowed
    assert not AttestedApprovalProvider(allow(), approved_by="   ").decide(_req()).allowed


def test_attested_identity_flows_to_evidence(evidence_home):
    journal = evidence_home / "journal.jsonl"

    @guard(
        action="att.act",
        journal=journal,
        approval_provider=AttestedApprovalProvider(allow(), approved_by="duty:officer"),
    )
    def act(x: int) -> int:
        return x

    act(1)
    assert json.loads(journal.read_text().splitlines()[0])["approved_by"] == "duty:officer"


# --- gateway -----------------------------------------------------------------


def test_gateway_choke_point(evidence_home):
    journal = evidence_home / "journal.jsonl"

    @guard(action="gw.refund", journal=journal, approval_provider=allow())
    def refund(amount_cents: int) -> int:
        return amount_cents

    gateway = ToolGateway.from_mapping({"refund": refund})
    assert gateway.names() == ("refund",)
    assert "refund" in gateway
    assert gateway.invoke("refund", 10) == 10
    with pytest.raises(ActionDenied):
        gateway.invoke("nope", 1)


def test_gateway_rejects_unguarded_and_duplicates():
    gateway = ToolGateway()

    def raw(x):
        return x

    with pytest.raises(ToolWrapError):
        gateway.register("raw", raw)
    with pytest.raises(ToolWrapError):
        gateway.register("", raw)
    with pytest.raises(ToolWrapError):
        gateway.register("x", 42)

    @guard(action="gw.ok", approval_provider=allow())
    def ok(x):
        return x

    gateway.register("ok", ok)
    with pytest.raises(ToolWrapError):
        gateway.register("ok", ok)
    lax = ToolGateway(require_guarded=False)
    lax.register("raw", raw)
    assert lax.invoke("raw", 1) == 1


def test_gateway_decorator_style(evidence_home):
    journal = evidence_home / "journal.jsonl"
    gateway = ToolGateway()

    @guard(action="gw.dec", journal=journal, approval_provider=allow())
    def tool(x: int) -> int:
        return x * 2

    gateway.register("double", tool)
    assert gateway.invoke("double", 21) == 42
