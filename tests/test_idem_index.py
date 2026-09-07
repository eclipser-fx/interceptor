"""In-process idempotency index: exact answers without per-call scans.

The index is an optimization only. Every test below compares the indexed
path against the scan path (``_USE_IDEM_INDEX`` forced off) so a divergence
fails loudly instead of silently over- or under-allowing.
"""

from __future__ import annotations

import threading
from pathlib import Path

import pytest

import interceptor.journal as journal_module
from helpers import allow, deny
from interceptor import guard
from interceptor.errors import DuplicateActionError
from interceptor.journal import (
    _IDEM_TABLES_CACHE,
    FileJournal,
    _idem_cache_key,
    find_blocking_idempotent_decision,
    find_completed_idempotent_decision,
)


@pytest.fixture
def no_index(monkeypatch: pytest.MonkeyPatch):
    """Force every check through the full scan (the pre-index behavior)."""

    monkeypatch.setattr(journal_module, "_USE_IDEM_INDEX", False)
    return None


def _ask(path: Path, action: str, key: str):
    return (
        find_completed_idempotent_decision(path, action, key),
        find_blocking_idempotent_decision(path, action, key),
    )


def _ask_scan(path: Path, action: str, key: str, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(journal_module, "_USE_IDEM_INDEX", False)
    try:
        return _ask(path, action, key)
    finally:
        monkeypatch.setattr(journal_module, "_USE_IDEM_INDEX", True)


def _ids(result) -> tuple[str | None, str | None]:
    completed, blocking = result
    completed_id = completed.get("event_id") if completed is not None else None
    blocking_id = blocking.get("event_id") if blocking is not None else None
    return completed_id, blocking_id


def test_index_matches_scan_at_every_step(
    evidence_home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    journal = tmp_path / "j.jsonl"

    @guard(action="idx.ok", journal=journal, approval_provider=allow(), idempotency_key="k")
    def ok(k: str) -> str:
        return "ok"

    @guard(action="idx.deny", journal=journal, approval_provider=deny(), idempotency_key="k")
    def denied(k: str) -> str:
        return "ok"  # pragma: no cover - denied, never runs

    @guard(action="idx.fail", journal=journal, approval_provider=allow(), idempotency_key="k")
    def fail(k: str) -> str:
        raise RuntimeError("boom")

    @guard(
        action="idx.dry",
        journal=journal,
        approval_provider=allow(),
        dry_run=True,
        idempotency_key="k",
    )
    def dry(k: str) -> str:
        return "ok"  # pragma: no cover - dry run, never runs

    @guard(action="idx.plain", journal=journal, approval_provider=allow())
    def plain(x: int) -> int:
        return x

    def check(step: str):
        assert _ids(_ask(journal, "idx.ok", "a")) == _ids(
            _ask_scan(journal, "idx.ok", "a", monkeypatch)
        ), step
        assert _ids(_ask(journal, "idx.fail", "f")) == _ids(
            _ask_scan(journal, "idx.fail", "f", monkeypatch)
        ), step

    check("empty journal")

    ok("a")
    check("after first success")
    with pytest.raises(DuplicateActionError):
        ok("a")
    check("after duplicate denial")

    with pytest.raises(RuntimeError):
        fail("f")
    check("after failure (retry must stay allowed)")
    assert find_blocking_idempotent_decision(journal, "idx.fail", "f") is None

    from interceptor.errors import ActionDenied

    with pytest.raises(ActionDenied):
        denied("d")
    check("after denial (denials never block)")

    assert dry("z") is None
    check("after dry run (dry runs never block)")

    plain(1)
    plain(2)
    check("after keyless calls")

    # A foreign writer bypassing FileJournal invalidates the cache; answers
    # must still match the scan (one fallback rebuild, then exact again).
    with open(journal, "ab") as handle:
        handle.write(b'{"not": "an event"}\n')
    check("after foreign garbage line")
    assert _ids(_ask(journal, "idx.ok", "a")) == _ids(
        _ask_scan(journal, "idx.ok", "a", monkeypatch)
    )

    # Wholesale replacement (restore/rotation): old keys must not block.
    journal.write_bytes(b"")
    check("after truncation to empty")
    assert find_blocking_idempotent_decision(journal, "idx.ok", "a") is None
    ok("b")
    check("after reuse with a new key")


def test_keyless_journal_builds_no_index(tmp_path: Path):
    journal = tmp_path / "j.jsonl"

    @guard(action="k.plain", journal=journal, approval_provider=allow())
    def plain(x: int) -> int:
        return x

    plain(1)
    plain(2)
    assert _IDEM_TABLES_CACHE == {}


def test_index_stores_only_blockable_decisions(tmp_path: Path):
    journal = tmp_path / "j.jsonl"

    @guard(action="s.ok", journal=journal, approval_provider=allow(), idempotency_key="k")
    def ok(k: str) -> str:
        return "ok"

    ok("a")
    key = _idem_cache_key(journal)
    entry = _IDEM_TABLES_CACHE.get(key)
    assert entry is not None
    _, _, tables = entry
    assert len(tables.decisions) == 1
    stored = next(iter(tables.decisions.values()))
    assert stored["action_name"] == "s.ok"
    assert stored["idempotency_key"] == "a"


def test_concurrent_same_key_executes_once(tmp_path: Path):
    journal = tmp_path / "j.jsonl"
    store = FileJournal(journal)

    @guard(action="race.act", journal=store, approval_provider=allow(), idempotency_key="k")
    def act(k: str) -> str:
        return "ok"

    barrier = threading.Barrier(8)
    outcomes: list[str] = []
    lock = threading.Lock()

    def worker() -> None:
        barrier.wait()
        try:
            act("same")
        except DuplicateActionError:
            result = "duplicate"
        else:
            result = "executed"
        with lock:
            outcomes.append(result)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert sorted(outcomes).count("executed") == 1
    assert sorted(outcomes).count("duplicate") == 7
    # The winner is recorded once; every loser recorded a denied duplicate.
    completed = find_completed_idempotent_decision(journal, "race.act", "same")
    assert completed is not None
    assert completed["decision"] == "allowed"


def _mp_race_worker(journal_str: str, home_str: str, gate, results) -> None:
    """One racer in a spawned interpreter: fresh index cache, shared file lock."""
    try:
        import os

        os.environ["INTERCEPTOR_EVIDENCE_HOME"] = home_str
        from helpers import allow
        from interceptor import guard
        from interceptor.errors import DuplicateActionError

        assert gate.wait(timeout=120)

        @guard(
            action="race.mp",
            journal=journal_str,
            approval_provider=allow(),
            idempotency_key="k",
        )
        def act(k: str) -> str:
            return "ok"

        try:
            act("same")
        except DuplicateActionError:
            results.put("duplicate")
        else:
            results.put("executed")
    except BaseException as exc:  # never hang the parent on worker failure
        try:
            results.put(f"error: {type(exc).__name__}: {exc}")
        except BaseException:
            pass


def test_multiprocess_same_key_executes_once(tmp_path: Path, evidence_home: Path):
    import multiprocessing as mp

    from interceptor.identity import LocalSigningIdentity
    from interceptor.verification import verify_journal

    LocalSigningIdentity.load_or_create()  # pre-create: children only load
    journal = tmp_path / "j.jsonl"
    ctx = mp.get_context("spawn")
    gate = ctx.Event()
    results = ctx.Queue()
    workers = [
        ctx.Process(target=_mp_race_worker, args=(str(journal), str(evidence_home), gate, results))
        for _ in range(4)
    ]
    for worker in workers:
        worker.start()
    gate.set()
    for worker in workers:
        worker.join(timeout=180)
    assert all(not worker.is_alive() for worker in workers)
    outcomes = sorted(results.get() for _ in workers)
    assert outcomes.count("executed") == 1, outcomes
    assert outcomes.count("duplicate") == 3, outcomes

    from interceptor.identity import load_trusted_public_keys

    keys = load_trusted_public_keys(evidence_home)
    assert verify_journal(journal, keys).valid
    completed = find_completed_idempotent_decision(journal, "race.mp", "same")
    assert completed is not None
    assert completed["decision"] == "allowed"


def test_completed_file_set_is_fifo_capped(tmp_path: Path):
    from interceptor.engine import (
        _COMPLETED_FILE,
        _COMPLETED_FILE_MAX,
        _is_completed,
        _mark_completed,
    )

    store = FileJournal(tmp_path / "j.jsonl")
    for index in range(_COMPLETED_FILE_MAX + 100):
        _mark_completed(store, "cap.act", f"key-{index}")
    assert len(_COMPLETED_FILE) == _COMPLETED_FILE_MAX
    assert not _is_completed(store, "cap.act", "key-0")
    assert _is_completed(store, "cap.act", f"key-{_COMPLETED_FILE_MAX + 99}")


def test_evicted_file_key_still_blocked_by_journal(tmp_path: Path):
    from interceptor.engine import _COMPLETED_FILE_MAX, _mark_completed

    journal = tmp_path / "j.jsonl"

    @guard(action="evict.act", journal=journal, approval_provider=allow(), idempotency_key="k")
    def act(k: str) -> str:
        return "ok"

    act("victim")
    store = FileJournal(journal)
    for index in range(_COMPLETED_FILE_MAX):
        _mark_completed(store, "evict.act", f"filler-{index}")
    # The in-process entry was evicted, but the journal remains authoritative.
    with pytest.raises(DuplicateActionError):
        act("victim")


def test_custom_store_completions_are_not_capped():
    from interceptor.engine import _COMPLETED_CUSTOM, _is_completed, _mark_completed

    class MemoryStore:
        @property
        def path(self):  # type: ignore[no-untyped-def]
            raise RuntimeError("no path")

        def append_event(self, build):  # type: ignore[no-untyped-def]
            raise AssertionError("not used")

    store = MemoryStore()
    for index in range(300):
        _mark_completed(store, "custom.act", f"key-{index}")  # type: ignore[arg-type]
    assert len(_COMPLETED_CUSTOM) == 300
    assert _is_completed(store, "custom.act", "key-0")  # type: ignore[arg-type]


def test_scan_fallback_without_index_flag(tmp_path: Path, no_index):
    journal = tmp_path / "j.jsonl"

    @guard(action="f.ok", journal=journal, approval_provider=allow(), idempotency_key="k")
    def ok(k: str) -> str:
        return "ok"

    ok("a")
    assert find_completed_idempotent_decision(journal, "f.ok", "a") is not None
    with pytest.raises(DuplicateActionError):
        ok("a")
