"""Second-party counter-signatures on checkpoints.

A journal signed by one local key is a self-attestation: anyone holding the
key can rewrite history and re-sign. A ``countersignature`` event raises the
bar to *two* keys held by *two* parties — typically the operator's local key
plus a manager's, auditor's, or automated witness's key kept elsewhere.

Flow: the operator runs ``checkpoint`` as usual, then a second party runs
``interceptor countersign --signing-key counter.pem``. That appends a
countersignature event (signed by the counter key, hash-chained like every
other event) committing to the newest checkpoint's ``(count, head)``. Forging
history afterwards requires both keys.

The checkpoint is looked up from the live journal without verification and
without holding the append lock: countersign while writers are quiesced, and
only countersign checkpoints you have verified (a second party signing blindly
attests to nothing). If a checkpoint lands mid-operation the attestation is
still truthful but no longer newest — the report flags ``superseded`` so you
can re-run.

The counter key must not live in the evidence home it attests to; verification
checks the countersignature against the same trusted keyring, so pass the
counter public key with ``--public-key`` (or register it in ``trusted_keys/``).
"""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path
from typing import Any

from .errors import CountersignError
from .identity import EphemeralSigningIdentity
from .journal import EVENT_SCHEMA_VERSION, FileJournal, finalize_event, new_event_id, utc_timestamp

COUNTERSIGNATURE_EVENT_TYPE = "countersignature"


@dataclasses.dataclass(frozen=True)
class CountersignatureReport:
    journal_path: Path
    countersignature_event: dict[str, Any]
    checkpoint_event_id: str
    checkpoint_count: int
    head_sha256: Any
    superseded: bool = False


def countersign_journal(
    path: str | Path,
    signing_key: str | Path,
    password: bytes | str | None = None,
) -> CountersignatureReport:
    """Counter-sign the newest checkpoint in *path* with an external key.

    Pass *password* for password-encrypted counter keys. Raises
    :class:`CountersignError` when the journal holds no checkpoint or the
    signing key cannot be loaded.
    """
    journal = Path(path)
    checkpoint = _newest_checkpoint(journal)
    if checkpoint is None:
        raise CountersignError(f"no checkpoint in {journal}; run `interceptor checkpoint` first")
    try:
        signer = EphemeralSigningIdentity.from_file(Path(signing_key), password)
    except Exception as exc:
        raise CountersignError(f"cannot load countersigning key: {exc}") from exc

    checkpoint_event_id = str(checkpoint["event_id"])
    checkpoint_count = checkpoint["checkpoint_count"]
    head_sha256 = checkpoint["head_sha256"]

    def build(previous_hash: str | None) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema_version": EVENT_SCHEMA_VERSION,
            "event_type": COUNTERSIGNATURE_EVENT_TYPE,
            "event_id": new_event_id(),
            "timestamp_utc": utc_timestamp(),
            "key_id": signer.key_id,
            "previous_event_hash": previous_hash,
            "checkpoint_event_id": checkpoint_event_id,
            "checkpoint_count": checkpoint_count,
            "head_sha256": head_sha256,
        }
        return finalize_event(payload, signer.sign)

    event = FileJournal(journal).append_event(build)
    # A checkpoint that landed between the lookup and the append is still a
    # truthful attestation, but it is no longer the newest — say so instead of
    # letting the operator believe otherwise.
    latest = _newest_checkpoint(journal)
    superseded = latest is None or str(latest.get("event_id")) != checkpoint_event_id
    return CountersignatureReport(
        journal_path=journal,
        countersignature_event=event,
        checkpoint_event_id=checkpoint_event_id,
        checkpoint_count=int(checkpoint_count),
        head_sha256=head_sha256,
        superseded=superseded,
    )


def _newest_checkpoint(journal: Path) -> dict[str, Any] | None:
    """The last checkpoint event in *journal*, or None."""
    newest: dict[str, Any] | None = None
    try:
        with open(journal, "rb") as handle:
            for raw in handle:
                line = raw.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line.decode("utf-8"))
                except (ValueError, UnicodeDecodeError):
                    continue
                if isinstance(event, dict) and event.get("event_type") == "checkpoint":
                    newest = event
    except OSError:
        return None
    return newest
