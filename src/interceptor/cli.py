"""``interceptor`` — offline inspection of a local evidence journal.

Every subcommand is read-only and works without a network. That is the point:
evidence you can only check by asking a service is evidence you are trusting
the service about.

    interceptor verify [--journal PATH] [--public-key PATH] [--checkpoint PATH] [--json]
    interceptor audit [--journal PATH] [--public-key PATH] [--json]
    interceptor checkpoint [--journal PATH] [--witness PATH] [--json]
    interceptor countersign --signing-key PATH [--journal PATH] [--json]
    interceptor resolve --decision ID --result completed|not-completed [--journal PATH]
    interceptor keygen --output PATH [--json]
    interceptor export [--journal PATH] [--format json|html] [--output PATH]
    interceptor stats [--journal PATH] [--json]
    interceptor archive [--journal PATH] [--keep N] [--json]
    interceptor key-info [--json]
    interceptor inspect [--journal PATH] [--json]

Exit codes: ``0`` success, ``1`` verification or inspection failure, ``2``
usage error (argparse exits ``2`` itself on a malformed command).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .audit import InvocationStatus, audit_journal
from .checkpoint import checkpoint_journal
from .errors import InterceptorError
from .identity import (
    LocalSigningIdentity,
    default_journal_path,
    evidence_home,
    key_id_for,
    load_public_key,
    load_trusted_public_keys,
    public_key_fingerprint,
    rotate_key,
)
from .privacy import inspect_journal
from .verification import PublicKeys, verify_journal

EXIT_OK = 0
EXIT_FAILURE = 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="interceptor",
        description="Verify and inspect a local evidence journal, offline.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    verify = subparsers.add_parser("verify", help="verify a journal's signatures and hash chain")
    verify.add_argument("--journal", type=Path, default=None, help="journal path")
    verify.add_argument(
        "--public-key",
        type=Path,
        action="append",
        default=None,
        help="verifying key path (repeatable; defaults to the trusted key set)",
    )
    verify.add_argument(
        "--checkpoint",
        type=Path,
        default=None,
        help="checkpoint witness file; the journal must cover its committed event count",
    )
    verify.add_argument("--json", action="store_true", help="emit JSON")

    verify_chain = subparsers.add_parser(
        "verify-chain", help="verify a journal plus every archived predecessor it links to"
    )
    verify_chain.add_argument("--journal", type=Path, default=None, help="live journal path")
    verify_chain.add_argument(
        "--public-key",
        type=Path,
        action="append",
        default=None,
        help="verifying key path (repeatable; defaults to the trusted key set)",
    )
    verify_chain.add_argument("--json", action="store_true", help="emit JSON")

    key_info = subparsers.add_parser("key-info", help="print the local signing identity")
    key_info.add_argument("--json", action="store_true", help="emit JSON")

    key_rotate = subparsers.add_parser(
        "key-rotate", help="replace the signing key, keeping old evidence verifiable"
    )
    key_rotate.add_argument("--journal", type=Path, default=None, help="journal to record to")
    key_rotate.add_argument(
        "--no-record",
        action="store_true",
        help="skip appending the signed rotation record",
    )
    key_rotate.add_argument("--json", action="store_true", help="emit JSON")

    checkpoint = subparsers.add_parser(
        "checkpoint",
        help="commit the journal tail to a durable, signed witness",
    )
    checkpoint.add_argument("--journal", type=Path, default=None, help="journal path")
    checkpoint.add_argument(
        "--witness",
        type=Path,
        default=None,
        help="witness file to write (default: <journal>.checkpoint)",
    )
    checkpoint.add_argument("--json", action="store_true", help="emit JSON")

    inspect = subparsers.add_parser(
        "inspect", help="report what a journal would disclose if shared"
    )
    inspect.add_argument("--journal", type=Path, default=None, help="journal path")
    inspect.add_argument(
        "--public-key",
        type=Path,
        default=None,
        help="verifying key path (defaults to the trusted key set)",
    )
    inspect.add_argument("--json", action="store_true", help="emit JSON")

    audit = subparsers.add_parser(
        "audit", help="pair decisions with outcomes and flag actions needing reconciliation"
    )
    audit.add_argument("--journal", type=Path, default=None, help="journal path")
    audit.add_argument(
        "--public-key",
        type=Path,
        action="append",
        default=None,
        help="verifying key path (repeatable; defaults to the trusted key set)",
    )
    audit.add_argument("--json", action="store_true", help="emit JSON")

    resolve = subparsers.add_parser(
        "resolve", help="record a signed operator resolution for a reconciled decision"
    )
    resolve.add_argument("--journal", type=Path, default=None, help="journal path")
    resolve.add_argument("--decision", required=True, help="decision event_id to resolve")
    resolve.add_argument(
        "--result",
        required=True,
        choices=["completed", "not-completed"],
        help="what the external-system check found",
    )
    resolve.add_argument("--note", default="", help="operator note (recorded, bounded)")
    resolve.add_argument("--json", action="store_true", help="emit JSON")

    countersign = subparsers.add_parser(
        "countersign", help="counter-sign the newest checkpoint with a second key"
    )
    countersign.add_argument("--journal", type=Path, default=None, help="journal path")
    countersign.add_argument(
        "--signing-key", type=Path, required=True, help="counter private key (PEM)"
    )
    countersign.add_argument("--json", action="store_true", help="emit JSON")

    keygen = subparsers.add_parser(
        "keygen", help="generate a standalone Ed25519 key (e.g. for counter-signing)"
    )
    keygen.add_argument("--output", type=Path, required=True, help="private key path to write")
    keygen.add_argument("--json", action="store_true", help="emit JSON")

    export = subparsers.add_parser(
        "export", help="write a self-contained evidence pack (JSON or HTML)"
    )
    export.add_argument("--journal", type=Path, default=None, help="journal path")
    export.add_argument(
        "--public-key",
        type=Path,
        action="append",
        default=None,
        help="verifying key path (repeatable; defaults to the trusted key set)",
    )
    export.add_argument("--format", choices=["json", "html"], default="json")
    export.add_argument("--output", type=Path, default=None, help="output path (default: stdout)")
    export.add_argument("--json", action="store_true", help="emit JSON (stats envelope)")

    stats = subparsers.add_parser("stats", help="operational counts over a journal")
    stats.add_argument("--journal", type=Path, default=None, help="journal path")
    stats.add_argument(
        "--public-key",
        type=Path,
        action="append",
        default=None,
        help="verifying key path (repeatable; defaults to the trusted key set)",
    )
    stats.add_argument("--json", action="store_true", help="emit JSON")

    archive = subparsers.add_parser(
        "archive", help="rotate the live journal to a timestamped file and start a linked successor"
    )
    archive.add_argument("--journal", type=Path, default=None, help="journal path")
    archive.add_argument(
        "--keep",
        type=int,
        default=None,
        help="retain only the newest N archives (oldest deleted)",
    )
    archive.add_argument("--json", action="store_true", help="emit JSON")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "verify":
            return _cmd_verify(args)
        if args.command == "verify-chain":
            return _cmd_verify_chain(args)
        if args.command == "key-info":
            return _cmd_key_info(args)
        if args.command == "key-rotate":
            return _cmd_key_rotate(args)
        if args.command == "keygen":
            return _cmd_keygen(args)
        if args.command == "inspect":
            return _cmd_inspect(args)
        if args.command == "audit":
            return _cmd_audit(args)
        if args.command == "checkpoint":
            return _cmd_checkpoint(args)
        if args.command == "countersign":
            return _cmd_countersign(args)
        if args.command == "resolve":
            return _cmd_resolve(args)
        if args.command == "export":
            return _cmd_export(args)
        if args.command == "stats":
            return _cmd_stats(args)
        if args.command == "archive":
            return _cmd_archive(args)
    except InterceptorError as exc:
        _fail(f"{type(exc).__name__}: {exc}", as_json=getattr(args, "json", False))
        return EXIT_FAILURE
    parser.error(f"unknown command {args.command!r}")  # exits with code 2
    return EXIT_FAILURE  # pragma: no cover - parser.error raises SystemExit


def _cmd_verify(args: argparse.Namespace) -> int:
    journal_path = args.journal or default_journal_path()

    if not journal_path.exists():
        _fail(f"no journal at {journal_path}", as_json=args.json)
        return EXIT_FAILURE

    try:
        keys = _resolve_verification_keys(args)
    except InterceptorError as exc:
        _fail(str(exc), as_json=args.json)
        return EXIT_FAILURE
    if not keys:
        _fail(
            "no trusted verification keys found; run `key-info` to create an "
            "identity or pass --public-key",
            as_json=args.json,
        )
        return EXIT_FAILURE

    result = verify_journal(journal_path, keys, checkpoint=args.checkpoint)
    payload: dict[str, Any] = {
        "journal": str(journal_path),
        "valid": result.valid,
        "events_verified": result.events_verified,
        "issues": [
            {"line_number": issue.line_number, "code": issue.code, "message": issue.message}
            for issue in result.issues
        ],
    }

    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    elif result.valid:
        print(f"OK  {journal_path}")
        print(f"    {result.events_verified} events, signatures and hash chain intact")
        if args.checkpoint:
            print("    checkpoint witness applied; truncation before it is detected")
        else:
            print("    note: tail truncation is detectable only with a checkpoint witness")
    else:
        print(f"FAIL  {journal_path}")
        print(f"      {result.events_verified} events verified before the first problem")
        for issue in result.issues:
            location = f"line {issue.line_number}" if issue.line_number else "file"
            print(f"      {location}: [{issue.code}] {issue.message}")

    return EXIT_OK if result.valid else EXIT_FAILURE


def _cmd_key_info(args: argparse.Namespace) -> int:
    identity = LocalSigningIdentity.load_or_create()
    public_path = identity.public_key_path
    trusted = load_trusted_public_keys(identity.home)
    payload = {
        "home": str(identity.home),
        "key_id": identity.key_id,
        "fingerprint": public_key_fingerprint(identity.public_key()),
        "public_key_path": str(public_path),
        "trusted_keys": len(trusted),
        "trusted_key_ids": [key_id_for(key) for key in trusted],
    }
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        for label, value in payload.items():
            print(f"{label:20} {value}")
    return EXIT_OK


def _cmd_key_rotate(args: argparse.Namespace) -> int:
    journal = getattr(args, "journal", None)
    record = not getattr(args, "no_record", False)
    identity = rotate_key(journal_path=journal, record=record)
    trusted = load_trusted_public_keys(identity.home)
    payload = {
        "home": str(identity.home),
        "key_id": identity.key_id,
        "fingerprint": public_key_fingerprint(identity.public_key()),
        "trusted_keys": len(trusted),
        "trusted_key_ids": [key_id_for(key) for key in trusted],
    }
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"Rotated signing identity in {identity.home}")
        print(f"  new key_id:   {identity.key_id}")
        print(f"  new fingerprint: {identity.fingerprint}")
        print(
            f"  {len(trusted)} key(s) now trusted; old events remain verifiable via the trusted set"
        )
    return EXIT_OK


def _resolve_verification_keys(args: argparse.Namespace) -> PublicKeys:
    """The keys to verify against: explicit ``--public-key`` list, or the set
    of keys the operator has registered as trusted."""
    if getattr(args, "public_key", None):
        return tuple(load_public_key(path) for path in args.public_key)
    return load_trusted_public_keys(evidence_home())


def _cmd_inspect(args: argparse.Namespace) -> int:
    journal_path = args.journal or default_journal_path()

    if not journal_path.exists():
        _fail(f"no journal at {journal_path}", as_json=args.json)
        return EXIT_FAILURE

    try:
        report = inspect_journal(journal_path, public_key_path=getattr(args, "public_key", None))
    except InterceptorError as exc:
        _fail(str(exc), as_json=args.json)
        return EXIT_FAILURE
    payload = {
        "journal": str(journal_path),
        "event_count": report.event_count,
        "decision_count": report.decision_count,
        "outcome_count": report.outcome_count,
        "safe_for_upload": report.safe_for_upload,
        "actions": [
            {
                "action_name": action.action_name,
                "classification": action.classification.value,
                "retained_parameter_names": list(action.retained_parameter_names),
                "explanation": action.explanation,
            }
            for action in report.actions
        ],
    }
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return EXIT_OK

    print(f"{journal_path}")
    print(
        f"  {report.event_count} events ({report.decision_count} decisions, "
        f"{report.outcome_count} outcomes)\n"
    )
    if not report.actions:
        print("  (no actions recorded)")
    for action in report.actions:
        print(f"  {action.action_name}")
        print(f"    classification: {action.classification.value}")
        if action.retained_parameter_names:
            print(f"    discloses:      {', '.join(action.retained_parameter_names)}")
        print(f"    {action.explanation}")
    print()
    if report.safe_for_upload:
        print("  Every recorded argument is redacted.")
    else:
        print("  Some arguments are recorded in the clear. Review before sharing.")
    return EXIT_OK


def _cmd_audit(args: argparse.Namespace) -> int:
    journal_path = args.journal or default_journal_path()
    if not journal_path.exists():
        _fail(f"no journal at {journal_path}", as_json=args.json)
        return EXIT_FAILURE

    try:
        keys = _resolve_verification_keys(args)
    except InterceptorError as exc:
        _fail(str(exc), as_json=args.json)
        return EXIT_FAILURE
    if not keys:
        _fail(
            "no trusted verification keys found; run `key-info` to create an "
            "identity or pass --public-key",
            as_json=args.json,
        )
        return EXIT_FAILURE

    report = audit_journal(journal_path, keys)
    counts = {status.value: 0 for status in InvocationStatus}
    for invocation in report.invocations:
        counts[invocation.status.value] += 1
    payload = {
        "journal": str(journal_path),
        "structurally_valid": report.structurally_valid,
        "needs_reconciliation": report.needs_reconciliation,
        "counts": counts,
        "invocations": [
            {
                "action_name": item.action_name,
                "action_id": item.action_id,
                "contract_hash": item.contract_hash,
                "input_hash": item.input_hash,
                "risk": item.risk,
                "approval_mode": item.approval_mode,
                "decision_event_id": item.decision_event_id,
                "decision": item.decision,
                "decision_timestamp_utc": item.decision_timestamp_utc,
                "outcome_event_id": item.outcome_event_id,
                "outcome_timestamp_utc": item.outcome_timestamp_utc,
                "status": item.status.value,
            }
            for item in report.invocations
        ],
        "issues": [
            {"code": issue.code, "message": issue.message, "event_id": issue.event_id}
            for issue in report.issues
        ],
    }
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"{journal_path}")
        for item in report.invocations:
            print(f"  {item.status.value:24} {item.action_name} ({item.risk})")
            print(f"    decision: {item.decision_event_id}")
            if item.outcome_event_id is not None:
                print(f"    outcome:  {item.outcome_event_id}")
        for issue in report.issues:
            location = f" ({issue.event_id})" if issue.event_id else ""
            print(f"  INVALID [{issue.code}]{location}: {issue.message}")
        if report.needs_reconciliation:
            print("  ATTENTION: one or more allowed actions failed or have no outcome.")
            print("  Check the external system before retrying; the side effect may have occurred.")
        elif report.structurally_valid:
            print("  No incomplete invocations. External side effects are still not proven.")

    ready = report.structurally_valid and not report.needs_reconciliation
    return EXIT_OK if ready else EXIT_FAILURE


def _cmd_checkpoint(args: argparse.Namespace) -> int:
    journal_path = args.journal or default_journal_path()
    report = checkpoint_journal(journal_path, witness_path=args.witness)
    payload = {
        "journal": str(journal_path),
        "event_id": report.checkpoint_event["event_id"],
        "checkpoint_count": report.checkpoint_count,
        "head_sha256": report.head_sha256,
        "witness_path": str(report.witness_path),
    }
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"Checkpointed {journal_path}")
        print(f"  events committed: {report.checkpoint_count}")
        print(f"  head sha256:      {report.head_sha256}")
        print(f"  witness:          {report.witness_path}")
        print("  Keep the witness somewhere the journal cannot reach; verify with")
        print(f"    interceptor verify --checkpoint {report.witness_path}")
    return EXIT_OK


def _cmd_resolve(args: argparse.Namespace) -> int:
    from .resolve import RESOLUTION_COMPLETED, RESOLUTION_NOT_COMPLETED, resolve_journal

    journal_path = args.journal or default_journal_path()
    resolution = RESOLUTION_COMPLETED if args.result == "completed" else RESOLUTION_NOT_COMPLETED
    report = resolve_journal(journal_path, args.decision, resolution, note=args.note)
    payload = {
        "journal": str(journal_path),
        "event_id": report.resolution_event["event_id"],
        "decision_event_id": report.decision_event_id,
        "resolution": report.resolution,
    }
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"Resolved {report.decision_event_id} as {report.resolution}")
        print(f"  event:   {report.resolution_event['event_id']}")
        print(f"  journal: {journal_path}")
    return EXIT_OK


def _cmd_countersign(args: argparse.Namespace) -> int:
    from .cosign import countersign_journal

    journal_path = args.journal or default_journal_path()
    report = countersign_journal(journal_path, args.signing_key)
    payload = {
        "journal": str(journal_path),
        "event_id": report.countersignature_event["event_id"],
        "checkpoint_event_id": report.checkpoint_event_id,
        "checkpoint_count": report.checkpoint_count,
        "head_sha256": report.head_sha256,
        "key_id": report.countersignature_event["key_id"],
    }
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"Counter-signed checkpoint {report.checkpoint_event_id}")
        print(f"  events committed: {report.checkpoint_count}")
        print(f"  head sha256:      {report.head_sha256}")
        print(f"  counter key_id:   {report.countersignature_event['key_id']}")
    return EXIT_OK


def _cmd_keygen(args: argparse.Namespace) -> int:
    from .identity import EphemeralSigningIdentity, generate_private_key

    output = Path(args.output)
    generate_private_key(output)
    signer = EphemeralSigningIdentity.from_file(output)
    payload = {
        "path": str(output),
        "key_id": signer.key_id,
        "fingerprint": signer.fingerprint,
    }
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"Wrote new Ed25519 private key to {output} (mode 0600)")
        print(f"  key_id:      {signer.key_id}")
        print(f"  fingerprint: {signer.fingerprint}")
        print("  Keep it somewhere the journal cannot reach.")
    return EXIT_OK


def _cmd_export(args: argparse.Namespace) -> int:
    from .export import export_journal, write_pack

    journal_path = args.journal or default_journal_path()
    if not journal_path.exists():
        _fail(f"no journal at {journal_path}", as_json=args.json)
        return EXIT_FAILURE
    try:
        keys = _resolve_verification_keys(args)
    except InterceptorError as exc:
        _fail(str(exc), as_json=args.json)
        return EXIT_FAILURE
    if not keys:
        _fail("no trusted verification keys found", as_json=args.json)
        return EXIT_FAILURE
    bundle = export_journal(journal_path, keys)
    if args.output is not None:
        write_pack(bundle, args.output, args.format)
        print(f"Wrote {args.format} evidence pack to {args.output}")
        return EXIT_OK
    if args.format == "html":
        from .export import render_html

        print(render_html(bundle))
    else:
        print(json.dumps(bundle, indent=2, sort_keys=True))
    valid = bundle["verification"]["valid"] and (bundle["audit"] or {}).get(
        "structurally_valid", False
    )
    return EXIT_OK if valid else EXIT_FAILURE


def _cmd_stats(args: argparse.Namespace) -> int:
    from .export import journal_stats
    from .verification import load_journal_snapshot

    journal_path = args.journal or default_journal_path()
    if not journal_path.exists():
        _fail(f"no journal at {journal_path}", as_json=args.json)
        return EXIT_FAILURE
    try:
        keys = _resolve_verification_keys(args)
    except InterceptorError as exc:
        _fail(str(exc), as_json=args.json)
        return EXIT_FAILURE
    if not keys:
        _fail("no trusted verification keys found", as_json=args.json)
        return EXIT_FAILURE
    snapshot = load_journal_snapshot(journal_path, keys)
    payload = {
        "journal": str(journal_path),
        "valid": snapshot.verification.valid,
        **journal_stats(snapshot),
    }
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"{journal_path}  ({'valid' if payload['valid'] else 'INVALID'})")
        print(
            f"  {payload['events']} events: {payload['decisions']} decisions, "
            f"{payload['outcomes']} outcomes, {payload['resolutions']} resolutions, "
            f"{payload['countersignatures']} countersignatures, "
            f"{payload['checkpoints']} checkpoints, {payload['archives']} archives, "
            f"{payload.get('rotations', 0)} rotations"
        )
        for action, count in sorted(payload["by_action"].items()):
            print(f"    {count:5}  {action}")
    return EXIT_OK if snapshot.verification.valid else EXIT_FAILURE


def _cmd_archive(args: argparse.Namespace) -> int:
    from .archive import archive_journal

    journal_path = args.journal or default_journal_path()
    report = archive_journal(journal_path, keep=args.keep)
    payload = {
        "journal": str(journal_path),
        "archived_path": str(report.archived_path),
        "event_id": report.archive_event["event_id"],
        "prior_count": report.prior_count,
        "prior_head": report.prior_head,
        "pruned": [str(p) for p in report.pruned],
    }
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"Archived {journal_path} to {report.archived_path}")
        print(f"  events archived: {report.prior_count}")
        print(f"  prior head:      {report.prior_head}")
        for pruned in report.pruned:
            print(f"  pruned:          {pruned}")
    return EXIT_OK


def _cmd_verify_chain(args: argparse.Namespace) -> int:
    from .archive import verify_archive_chain

    journal_path = args.journal or default_journal_path()
    if not journal_path.exists():
        _fail(f"no journal at {journal_path}", as_json=args.json)
        return EXIT_FAILURE
    try:
        keys = _resolve_verification_keys(args)
    except InterceptorError as exc:
        _fail(str(exc), as_json=args.json)
        return EXIT_FAILURE
    if not keys:
        _fail(
            "no trusted verification keys found; run `key-info` to create an "
            "identity or pass --public-key",
            as_json=args.json,
        )
        return EXIT_FAILURE
    report = verify_archive_chain(journal_path, keys)
    payload = {
        "journal": str(journal_path),
        "valid": report.valid,
        "files_checked": list(report.files_checked),
        "issues": [
            {"file": issue.file, "code": issue.code, "message": issue.message}
            for issue in report.issues
        ],
    }
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    elif report.valid:
        print(f"OK  {journal_path} (+{len(report.files_checked) - 1} archives)")
        for checked in report.files_checked:
            print(f"    verified {checked}")
    else:
        print(f"FAIL  {journal_path}")
        for issue in report.issues:
            print(f"      {issue.file}: [{issue.code}] {issue.message}")
    return EXIT_OK if report.valid else EXIT_FAILURE


def _fail(message: str, *, as_json: bool) -> None:
    if as_json:
        print(json.dumps({"error": message}, indent=2), file=sys.stderr)
    else:
        print(f"error: {message}", file=sys.stderr)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
