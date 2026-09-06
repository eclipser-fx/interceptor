"""WitnessFreshnessProvider: deny unless the off-host witness is fresh."""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from helpers import allow
from interceptor import WitnessFreshnessProvider, guard
from interceptor.approval import ApprovalRequest
from interceptor.errors import ActionDenied
from interceptor.policy import AllOf


def _req(risk: str = "high") -> ApprovalRequest:
    return ApprovalRequest(
        action_name="billing.refund",
        risk=risk,
        approval_mode="required",
        redacted_input_summary="{}",
        input_hash="h",
        contract_hash="c",
    )


def _touch(path: Path, *, mtime: float) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("witness")
    os.utime(path, (mtime, mtime))
    return path


def test_fresh_witness_allows(tmp_path: Path):
    now = time.time()
    _touch(tmp_path / "latest.checkpoint", mtime=now - 10)
    provider = WitnessFreshnessProvider(tmp_path, 300, clock=lambda: now)
    decision = provider.decide(_req())
    assert decision.allowed
    assert "fresh" in decision.reason


def test_stale_witness_denies(tmp_path: Path):
    now = time.time()
    _touch(tmp_path / "latest.checkpoint", mtime=now - 1000)
    provider = WitnessFreshnessProvider(tmp_path, 300, clock=lambda: now)
    decision = provider.decide(_req())
    assert not decision.allowed
    assert "stale" in decision.reason


def test_missing_witness_denies(tmp_path: Path):
    provider = WitnessFreshnessProvider(tmp_path / "empty", 300, clock=lambda: time.time())
    assert not provider.decide(_req()).allowed


def test_missing_file_in_existing_dir_denies(tmp_path: Path):
    tmp_path.mkdir(exist_ok=True)
    provider = WitnessFreshnessProvider(tmp_path, 60, clock=lambda: time.time())
    decision = provider.decide(_req())
    assert not decision.allowed
    assert "no witness" in decision.reason


def test_risk_subset_bypasses_low_risk(tmp_path: Path):
    now = time.time()
    _touch(tmp_path / "latest.checkpoint", mtime=now - 10_000)
    provider = WitnessFreshnessProvider(
        tmp_path, 300, risks={"high", "critical"}, clock=lambda: now
    )
    assert provider.decide(_req("low")).allowed
    assert not provider.decide(_req("high")).allowed
    assert not provider.decide(_req("critical")).allowed


def test_future_mtime_is_fresh(tmp_path: Path):
    now = time.time()
    _touch(tmp_path / "latest.checkpoint", mtime=now + 60)
    provider = WitnessFreshnessProvider(tmp_path, 300, clock=lambda: now)
    assert provider.decide(_req()).allowed


def test_clock_failure_fails_closed(tmp_path: Path):
    _touch(tmp_path / "latest.checkpoint", mtime=time.time())

    def _boom() -> float:
        raise RuntimeError("clock broken")

    provider = WitnessFreshnessProvider(tmp_path, 300, clock=_boom)
    assert not provider.decide(_req()).allowed


def test_bad_args_rejected(tmp_path: Path):
    with pytest.raises(ValueError):
        WitnessFreshnessProvider(tmp_path, 0)
    with pytest.raises(ValueError):
        WitnessFreshnessProvider(tmp_path, -5)
    with pytest.raises(ValueError):
        WitnessFreshnessProvider(tmp_path, 60, risks={"bogus"})
    with pytest.raises(ValueError):
        WitnessFreshnessProvider(tmp_path, 60, witness_filename="sub/dir")


def test_guard_denies_and_records_when_stale(evidence_home: Path, tmp_path: Path):
    now = time.time()
    witness_dir = tmp_path / "witness"
    witness_dir.mkdir()
    _touch(witness_dir / "latest.checkpoint", mtime=now - 3600)
    provider = AllOf([allow(), WitnessFreshnessProvider(witness_dir, 300, clock=lambda: now)])

    @guard(
        action="billing.refund",
        risk="high",
        journal=tmp_path / "j.jsonl",
        approval_provider=provider,
    )
    def refund(order_id: str) -> str:
        return "ok"

    with pytest.raises(ActionDenied):
        refund("o1")
