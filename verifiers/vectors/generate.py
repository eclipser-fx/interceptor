#!/usr/bin/env python3
"""Generate cross-language evidence vectors (v1).

Each vector is a journal plus its verification expectations, committed under
``verifiers/vectors/v1/*.json`` so independent verifiers (Python, Node, and
future SDKs) check the same artifacts. Journal lines are stored verbatim —
verifiers must hash the exact bytes.

Layout per file::

    {"name": ..., "public_keys": [<PEM>, ...], "journal": [<line>, ...],
     "expect": {"valid": bool, "events_verified": int, "codes": [<issue codes>]}}

Regenerate with: ``python verifiers/vectors/generate.py`` from the repo root.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "src"))

from cryptography.hazmat.primitives import serialization  # noqa: E402

from interceptor import (  # noqa: E402
    archive_journal,
    audit_journal,
    checkpoint_journal,
    countersign_journal,
    guard,
    resolve_journal,
    verify_journal,
)
from interceptor.errors import ActionDenied, DuplicateActionError  # noqa: E402
from interceptor.identity import (  # noqa: E402
    EphemeralSigningIdentity,
    LocalSigningIdentity,
    key_id_for,
    load_public_key,
    load_trusted_public_keys,
    rotate_key,
)

OUT = Path(__file__).resolve().parent / "v1"

#: Fixed generation time so vectors are byte-stable across runs. Real journals
#: carry wall-clock timestamps; vectors pin one to keep committed diffs
#: reviewable (verifiers must accept any timestamp shape regardless).
VECTOR_TIMESTAMP = "2026-01-01T00:00:00.000000Z"


def _freeze_time_and_ids() -> None:
    """Pin timestamps, event ids, and archive names for deterministic vectors."""
    import itertools
    from datetime import datetime, timezone

    import interceptor.archive as _archive
    import interceptor.checkpoint as _checkpoint
    import interceptor.cosign as _cosign
    import interceptor.engine as _engine
    import interceptor.journal as _journal
    import interceptor.resolve as _resolve

    counter = itertools.count(1)

    def _new_id() -> str:
        return f"00000000-0000-4000-8000-{next(counter):012d}"

    for module in (_journal, _engine, _archive, _checkpoint, _cosign, _resolve):
        module.utc_timestamp = lambda: VECTOR_TIMESTAMP  # type: ignore[attr-defined]
        module.new_event_id = _new_id  # type: ignore[attr-defined]

    class _FrozenDateTime(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime(2026, 1, 1, tzinfo=timezone.utc)

    _archive.datetime = _FrozenDateTime  # type: ignore[attr-defined]


def _seed_home(name: str) -> Path:
    """Fresh evidence home with a deterministic key for vector *name*."""
    import hashlib
    import stat

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    home = _new_home()
    private = Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(f"interceptor vector {name}".encode()).digest()
    )
    public = private.public_key()
    home.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(home, stat.S_IRWXU)
    except OSError:
        pass
    (home / "signing_key.pem").write_bytes(
        private.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    try:
        os.chmod(home / "signing_key.pem", stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass
    pub_pem = public.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    (home / "verify_key.pem").write_bytes(pub_pem)
    trusted = home / "trusted_keys"
    trusted.mkdir(exist_ok=True)
    from interceptor.identity import public_key_fingerprint

    (trusted / f"{public_key_fingerprint(public)}.pem").write_bytes(pub_pem)
    return home


def _pem(public_key) -> str:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def _seed_private_key(seed: str):
    """Deterministic private key (vector fixtures only, never production)."""
    import hashlib

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(seed.encode()).digest())


def _write_seed_key(path: Path, seed: str) -> None:
    """Write a deterministic private key (vector fixtures only, never production)."""
    key = _seed_private_key(seed)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )


def _new_home() -> Path:
    tmp = Path(tempfile.mkdtemp(prefix="vector-home-"))
    os.environ["INTERCEPTOR_EVIDENCE_HOME"] = str(tmp)
    from interceptor.engine import reset_idempotency_state
    from interceptor.observer import reset_notifications

    reset_notifications()
    reset_idempotency_state()
    return tmp


def _emit(name: str, journal: Path, keys: list, audit: bool = False) -> None:
    lines = [line for line in journal.read_text().splitlines() if line.strip()]
    pubs = [load_public_key(Path(k)) if isinstance(k, (str, Path)) else k for k in keys]
    result = verify_journal(journal, pubs)
    expect: dict = {
        "valid": result.valid,
        "events_verified": result.events_verified,
        "codes": sorted({issue.code for issue in result.issues}),
        "issues": [f"{issue.line_number}:{issue.code}" for issue in result.issues],
    }
    if audit and result.valid:
        report = audit_journal(journal, pubs)
        expect["audit"] = {
            "structurally_valid": report.structurally_valid,
            "statuses": sorted(inv.status.value for inv in report.invocations),
            "issue_codes": sorted({issue.code for issue in report.issues}),
        }
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / f"{name}.json").write_text(
        json.dumps(
            {
                "name": name,
                "public_keys": [_pem(k) for k in pubs],
                "journal": lines,
                "expect": expect,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    print(f"wrote {name}.json valid={result.valid} events={result.events_verified}")


def main() -> None:
    sys.path.insert(0, str(ROOT / "tests"))
    from helpers import StaticProvider

    _freeze_time_and_ids()
    allow = StaticProvider("allowed", "vector allow")

    # 1. Basic guarded call with receipt, redaction, and float amount.
    home = _seed_home("basic")
    journal = home / "journal.jsonl"

    @guard(
        action="billing.refund",
        risk="high",
        journal=journal,
        approval_provider=allow,
        idempotency_key="order_id",
        receipt_from=lambda r: {"processor": "acme", "refund_id": r["id"]},
    )
    def refund(order_id: str, amount: float, api_key: str = "secret") -> dict:
        return {"id": "re_1", "amount": amount}

    refund("o-1", 19.99)
    _emit("basic", journal, [home / "verify_key.pem"], audit=True)

    # 2. Denied call.
    home = _seed_home("denied")
    journal = home / "journal.jsonl"
    deny = StaticProvider("denied", "vector deny")

    @guard(action="ops.delete", risk="critical", journal=journal, approval_provider=deny)
    def delete(name: str) -> str:
        return name

    try:
        delete("prod")
    except ActionDenied:
        pass
    _emit("denied", journal, [home / "verify_key.pem"], audit=True)

    # 3. Idempotent duplicate.
    home = _seed_home("idempotent-duplicate")
    journal = home / "journal.jsonl"

    @guard(
        action="billing.refund",
        journal=journal,
        approval_provider=allow,
        idempotency_key="order_id",
    )
    def refund2(order_id: str) -> str:
        return "ok"

    refund2("dup-1")
    try:
        refund2("dup-1")
    except DuplicateActionError:
        pass
    _emit("idempotent-duplicate", journal, [home / "verify_key.pem"], audit=True)

    # 4. Dry run.
    home = _seed_home("dry-run")
    journal = home / "journal.jsonl"

    @guard(action="ops.plan", journal=journal, approval_provider=allow, dry_run=True)
    def plan(name: str) -> str:
        raise AssertionError("must not execute")

    plan("x")
    _emit("dry-run", journal, [home / "verify_key.pem"], audit=True)

    # 5. Rotation: old key, rotation record, new key.
    home = _seed_home("rotation")
    journal = home / "journal.jsonl"

    @guard(action="vec.act", journal=journal, approval_provider=allow)
    def act(x: int) -> int:
        return x

    act(1)
    rotate_key(new_key=_seed_private_key("interceptor vector rotation successor"))
    act(2)
    _emit("rotation", journal, list(sorted((home / "trusted_keys").glob("*.pem"))), audit=True)

    # 6. Checkpoint + resolution + countersignature.
    home = _seed_home("checkpoint-resolution-countersignature")
    journal = home / "journal.jsonl"

    @guard(action="vec.ops", journal=journal, approval_provider=allow)
    def op(x: int) -> int:
        if x < 0:
            raise ValueError("negative")
        return x

    op(1)
    try:
        op(-1)
    except ValueError:
        pass
    checkpoint_journal(journal)
    report = audit_journal(journal, load_trusted_public_keys(home))
    resolve_journal(journal, report.invocations[1].decision_event_id, "confirmed_completed")
    counter = home / "counter.pem"
    _write_seed_key(counter, "interceptor vector counter")
    countersign_journal(journal, counter)
    counter_pub = home / "counter-pub.pem"
    counter_pub.write_bytes(
        EphemeralSigningIdentity.from_file(counter)
        .public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    _emit(
        "checkpoint-resolution-countersignature",
        journal,
        [home / "verify_key.pem", counter_pub],
        audit=True,
    )

    # 7. Archive: live file whose first line links the predecessor.
    home = _seed_home("archive-live")
    journal = home / "journal.jsonl"

    @guard(action="vec.arch", journal=journal, approval_provider=allow)
    def a(x: int) -> int:
        return x

    a(1)
    archive_journal(journal)
    a(2)
    _emit("archive-live", journal, [home / "verify_key.pem"])

    # 8. Tampered event (risk rewritten): must fail with hash_mismatch.
    home = _seed_home("tampered")
    journal = home / "journal.jsonl"

    @guard(action="vec.tamper", journal=journal, approval_provider=allow)
    def t(x: int) -> int:
        return x

    t(5)
    lines = journal.read_text().splitlines()
    event = json.loads(lines[0])
    event["risk"] = "low"
    lines[0] = json.dumps(event, sort_keys=True, separators=(",", ":"))
    journal.write_text("\n".join(lines) + "\n")
    _emit("tampered", journal, [home / "verify_key.pem"])

    # 9. Truncated tail with no witness: a prefix is still a valid chain.
    # This documents the documented limit, it does not bless it.
    home = _seed_home("truncated-tail-no-witness")
    journal = home / "journal.jsonl"

    @guard(action="vec.trunc", journal=journal, approval_provider=allow)
    def u(x: int) -> int:
        return x

    u(1)
    u(2)
    lines = journal.read_text().splitlines()
    journal.write_text("\n".join(lines[:2]) + "\n")
    _emit("truncated-tail-no-witness", journal, [home / "verify_key.pem"])

    # 10. Key id sanity.
    _ = key_id_for(LocalSigningIdentity.load_or_create().public_key())
    print("vectors complete")


if __name__ == "__main__":
    main()
