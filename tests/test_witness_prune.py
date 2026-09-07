"""Witness retention: prune oldest shipped witnesses, keep the newest N."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from helpers import allow
from interceptor import guard, prune_witnesses, verify_journal, witness_journal
from interceptor.errors import JournalError
from interceptor.identity import load_trusted_public_keys


def _stamp(path: Path, *, mtime_ns: int) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("witness")
    os.utime(path, ns=(mtime_ns, mtime_ns))
    return path


def test_prune_keeps_newest_and_never_latest(tmp_path: Path):
    witness_dir = tmp_path / "w"
    base = 1_700_000_000_000_000_000
    for index in range(5):
        _stamp(witness_dir / f"checkpoint-2024010{index}T000000Z.checkpoint", mtime_ns=base + index)
    latest = _stamp(witness_dir / "latest.checkpoint", mtime_ns=base - 1)

    report = prune_witnesses(witness_dir, keep=2)

    assert [p.name for p in report.deleted] == [
        "checkpoint-20240100T000000Z.checkpoint",
        "checkpoint-20240101T000000Z.checkpoint",
        "checkpoint-20240102T000000Z.checkpoint",
    ]
    assert [p.name for p in report.kept] == [
        "checkpoint-20240103T000000Z.checkpoint",
        "checkpoint-20240104T000000Z.checkpoint",
    ]
    assert latest.exists()
    assert sorted(p.name for p in witness_dir.iterdir()) == [
        "checkpoint-20240103T000000Z.checkpoint",
        "checkpoint-20240104T000000Z.checkpoint",
        "latest.checkpoint",
    ]


def test_prune_keep_more_than_present_deletes_nothing(tmp_path: Path):
    witness_dir = tmp_path / "w"
    _stamp(witness_dir / "checkpoint-20240101T000000Z.checkpoint", mtime_ns=100)
    report = prune_witnesses(witness_dir, keep=10)
    assert report.deleted == ()
    assert len(report.kept) == 1


def test_prune_empty_dir_is_noop(tmp_path: Path):
    witness_dir = tmp_path / "w"
    witness_dir.mkdir()
    report = prune_witnesses(witness_dir, keep=4)
    assert report.kept == ()
    assert report.deleted == ()


def test_prune_rejects_bad_args(tmp_path: Path):
    with pytest.raises(ValueError):
        prune_witnesses(tmp_path, keep=0)
    with pytest.raises(ValueError):
        prune_witnesses(tmp_path, keep=-3)
    with pytest.raises(JournalError):
        prune_witnesses(tmp_path / "missing", keep=2)


def test_prune_keeps_newest_bound_covering_journal(evidence_home: Path, tmp_path: Path):
    journal = evidence_home / "journal.jsonl"

    @guard(action="w.act", journal=journal, approval_provider=allow())
    def act(x: int) -> int:
        return x

    witness_dir = tmp_path / "w"
    act(1)
    first = witness_journal(journal, witness_dir)
    act(2)
    second = witness_journal(journal, witness_dir)
    assert first.shipped_path != second.shipped_path

    report = prune_witnesses(witness_dir, keep=1)
    assert report.deleted == (first.shipped_path,)
    assert report.kept == (second.shipped_path,)

    keys = load_trusted_public_keys(evidence_home)
    assert verify_journal(journal, keys, checkpoint=second.shipped_path).valid


def test_prune_cli(evidence_home: Path, tmp_path: Path, capsys):
    from interceptor.cli import EXIT_FAILURE, EXIT_OK, main

    journal = evidence_home / "journal.jsonl"

    @guard(action="w.act", journal=journal, approval_provider=allow())
    def act(x: int) -> int:
        return x

    out_dir = tmp_path / "w"
    act(1)
    assert main(["witness", "--journal", str(journal), "--witness-dir", str(out_dir)]) == EXIT_OK
    capsys.readouterr()
    assert (
        main(["witness-prune", "--witness-dir", str(out_dir), "--keep", "4", "--json"]) == EXIT_OK
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["keep"] == 4
    assert payload["deleted"] == []
    assert len(payload["kept"]) == 1

    assert main(["witness-prune", "--witness-dir", str(tmp_path / "nope"), "--keep", "4"]) == (
        EXIT_FAILURE
    )
