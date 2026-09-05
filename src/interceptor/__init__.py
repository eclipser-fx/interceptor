"""Approval-gated, tamper-evident evidence for consequential Python calls.

Decorate a function that does something you would not want to happen twice, or
silently, or unapproved:

.. code-block:: python

    from interceptor import guard

    @guard(action="billing.refund", risk="high")
    def refund(customer_id: str, amount_cents: int, api_key: str) -> dict:
        return payments.refund(customer_id, amount_cents)

Every call now produces two signed, hash-chained journal entries — a
``decision`` recorded *before* execution and an ``outcome`` recorded after —
and prompts for approval unless a provider says otherwise. Sensitive arguments
never reach the journal, the prompt, or any hash.

There is no service behind this. No account, no API key, no network: the
guarantee is a local Ed25519 key and an append-only file you can verify
offline with ``interceptor verify``.

What the evidence proves, precisely, is in ``docs/THREAT_MODEL.md``. It is
worth reading before relying on it — in particular, truncating the *tail* of a
journal is not detectable from the journal alone.
"""

from __future__ import annotations

from .approval import (
    ApprovalDecision,
    ApprovalProvider,
    ApprovalRequest,
    AutoAllowProvider,
    TerminalApprovalProvider,
)
from .approve_server import ApprovalServer, ServerApprovalProvider
from .archive import (
    ArchiveChainIssue,
    ArchiveChainReport,
    ArchiveReport,
    archive_journal,
    verify_archive_chain,
)
from .audit import (
    AuditedInvocation,
    AuditIssue,
    AuditReport,
    InvocationStatus,
    audit_journal,
)
from .canonical import REDACTED, Canonicalized, canonical_hash, canonicalize
from .checkpoint import CheckpointReport, checkpoint_journal
from .contracts import ActionContract, ParameterDescriptor
from .cosign import CountersignatureReport, countersign_journal
from .engine import (
    IdempotencyKeySpec,
    ReceiptExtractor,
    SpendExtractor,
    reset_idempotency_state,
)
from .errors import (
    ActionDenied,
    ApprovalError,
    ApprovalUnavailableError,
    ArchiveError,
    CanonicalizationError,
    ContractError,
    CountersignError,
    DuplicateActionError,
    EvidenceAuditError,
    EvidencePersistenceError,
    EvidencePrivacyInspectionError,
    ExecutionCompletedEvidenceError,
    IdentityError,
    InterceptorError,
    JournalError,
    PolicyError,
    RedactionError,
    ResolutionError,
    SigningError,
    ToolWrapError,
    UnsupportedFunctionError,
    VerificationError,
)
from .errors import (
    ExecutionCompletedEvidenceError as EvidenceIncompleteError,
)
from .export import (
    EVIDENCE_PACK_FORMAT,
    export_journal,
    journal_stats,
    render_html,
    write_pack,
)
from .gateway import ToolGateway
from .guard import guard
from .identity import (
    CallbackSigningIdentity,
    EphemeralSigningIdentity,
    LocalSigningIdentity,
    SigningIdentity,
    evidence_home,
    generate_private_key,
    load_private_key,
    load_public_key,
    record_rotation_event,
    rotate_key,
)
from .journal import (
    FileJournal,
    JournalStore,
    find_blocking_idempotent_decision,
    find_completed_idempotent_decision,
)
from .observer import ActionObserver
from .policy import (
    AllOf,
    AllowListProvider,
    AnyOf,
    AttestedApprovalProvider,
    BudgetProvider,
    CachedApprovalProvider,
    CombinedProvider,
    FileBudgetProvider,
    FileRateLimitProvider,
    FileSpendingBudgetProvider,
    PredicateProvider,
    QuorumApprovalProvider,
    RateLimitProvider,
    Rule,
    RuleProvider,
    SpendingBudgetProvider,
    TimeoutApprovalProvider,
    load_policy_file,
)
from .privacy import (
    ActionPrivacyInspection,
    EvidencePrivacyReport,
    PrivacyClassification,
    inspect_journal,
)
from .redaction import (
    DEFAULT_VALUE_PATTERNS,
    SENSITIVE_NAMES,
    build_sensitive_set,
    compile_value_patterns,
    value_matches_patterns,
)
from .resolve import (
    RESOLUTION_COMPLETED,
    RESOLUTION_NOT_COMPLETED,
    ResolutionReport,
    resolve_journal,
)
from .schemas import as_openai_tool, describe_tool, mcp_tool
from .shipping import CallableSink, EventSink, FanoutJournalStore, FileMirrorSink
from .verification import VerificationIssue, VerificationResult, verify_journal
from .wrap_tool import wrap_tool, wrap_tools

_FALLBACK_VERSION = "0.1.0"


def _package_version() -> str:
    """The installed package version, with a source-tree fallback.

    ``pyproject.toml`` is the single source of truth; this reads the installed
    distribution's metadata so the two cannot drift apart.
    """
    try:
        from importlib.metadata import version

        return version("interceptor")
    except Exception:  # pragma: no cover - running from a source checkout
        return _FALLBACK_VERSION


__version__ = _package_version()

__all__ = [
    "DEFAULT_VALUE_PATTERNS",
    "EVIDENCE_PACK_FORMAT",
    "REDACTED",
    "RESOLUTION_COMPLETED",
    "RESOLUTION_NOT_COMPLETED",
    "SENSITIVE_NAMES",
    "ActionContract",
    "ActionDenied",
    "ActionObserver",
    "ActionPrivacyInspection",
    "AllOf",
    "AllowListProvider",
    "AnyOf",
    "ApprovalDecision",
    "ApprovalError",
    "ApprovalProvider",
    "ApprovalRequest",
    "ApprovalServer",
    "ApprovalUnavailableError",
    "ArchiveChainIssue",
    "ArchiveChainReport",
    "ArchiveError",
    "ArchiveReport",
    "AttestedApprovalProvider",
    "AuditIssue",
    "AuditReport",
    "AuditedInvocation",
    "AutoAllowProvider",
    "BudgetProvider",
    "CachedApprovalProvider",
    "CallableSink",
    "CallbackSigningIdentity",
    "CanonicalizationError",
    "Canonicalized",
    "CheckpointReport",
    "CombinedProvider",
    "ContractError",
    "CountersignError",
    "CountersignatureReport",
    "DuplicateActionError",
    "EphemeralSigningIdentity",
    "EventSink",
    "EvidenceAuditError",
    "EvidenceIncompleteError",
    "EvidencePersistenceError",
    "EvidencePrivacyInspectionError",
    "EvidencePrivacyReport",
    "ExecutionCompletedEvidenceError",
    "FanoutJournalStore",
    "FileBudgetProvider",
    "FileJournal",
    "FileMirrorSink",
    "FileRateLimitProvider",
    "FileSpendingBudgetProvider",
    "IdempotencyKeySpec",
    "IdentityError",
    "InterceptorError",
    "InvocationStatus",
    "JournalError",
    "JournalStore",
    "LocalSigningIdentity",
    "ParameterDescriptor",
    "PolicyError",
    "PredicateProvider",
    "PrivacyClassification",
    "QuorumApprovalProvider",
    "RateLimitProvider",
    "ReceiptExtractor",
    "RedactionError",
    "ResolutionError",
    "ResolutionReport",
    "Rule",
    "RuleProvider",
    "ServerApprovalProvider",
    "SigningError",
    "SigningIdentity",
    "SpendExtractor",
    "SpendingBudgetProvider",
    "TerminalApprovalProvider",
    "TimeoutApprovalProvider",
    "ToolGateway",
    "ToolWrapError",
    "UnsupportedFunctionError",
    "VerificationError",
    "VerificationIssue",
    "VerificationResult",
    "__version__",
    "archive_journal",
    "as_openai_tool",
    "audit_journal",
    "build_sensitive_set",
    "canonical_hash",
    "canonicalize",
    "checkpoint_journal",
    "compile_value_patterns",
    "countersign_journal",
    "describe_tool",
    "evidence_home",
    "export_journal",
    "find_blocking_idempotent_decision",
    "find_completed_idempotent_decision",
    "generate_private_key",
    "guard",
    "inspect_journal",
    "journal_stats",
    "load_policy_file",
    "load_private_key",
    "load_public_key",
    "mcp_tool",
    "record_rotation_event",
    "render_html",
    "reset_idempotency_state",
    "resolve_journal",
    "rotate_key",
    "value_matches_patterns",
    "verify_archive_chain",
    "verify_journal",
    "wrap_tool",
    "wrap_tools",
    "write_pack",
]
