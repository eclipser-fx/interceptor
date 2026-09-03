"""Action contracts: the code declaration IS the registration.

An :class:`ActionContract` is derived deterministically from the decorated
function and the ``@guard`` arguments. No registry call is made in
Embedded mode; the contract (and its stable ``contract_hash``) is what a
future observer integration could synchronize with the guard action
registry.

Determinism rules:

* the contract never contains timestamps, absolute filesystem paths, memory
  addresses, or interpreter-specific values;
* parameter descriptors come from :func:`inspect.signature`;
* annotations are rendered to stable strings (dotted type names where
  possible), never serialized as Python objects;
* ``code_fingerprint`` is the SHA-256 of the function's dedented source when
  source is available, and ``None`` otherwise (a missing source never invents
  a fingerprint and does not fail contract generation);
* ``contract_hash`` is the SHA-256 hex of the canonical JSON of every
  contract field except ``contract_hash`` itself.
"""

from __future__ import annotations

import dataclasses
import inspect
import re
import textwrap
from collections.abc import Callable
from typing import Any, cast

from .canonical import canonical_json_bytes, sha256_hex
from .errors import ContractError, UnsupportedFunctionError

CONTRACT_SCHEMA_VERSION = "1"
EXECUTION_MODE_EMBEDDED = "embedded"

RISK_LEVELS = ("low", "medium", "high", "critical")
APPROVAL_MODES = ("required", "never")

_ACTION_NAME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_.:-]{0,127}$")


@dataclasses.dataclass(frozen=True)
class ParameterDescriptor:
    name: str
    kind: str
    has_default: bool
    annotation: str | None


@dataclasses.dataclass(frozen=True)
class ActionContract:
    schema_version: str
    action_name: str
    module: str
    qualified_name: str
    risk: str
    approval_mode: str
    execution_mode: str
    parameter_descriptors: tuple[ParameterDescriptor, ...]
    code_fingerprint: str | None
    contract_hash: str

    @property
    def action_id(self) -> str:
        """Deterministic code-location identity (module + qualified name)."""
        return f"{self.module}.{self.qualified_name}"


def validate_action_name(name: str) -> str:
    if not isinstance(name, str) or not _ACTION_NAME_RE.match(name):
        raise ContractError(
            f"invalid action name {name!r}: expected a stable logical name "
            "(letters, digits, '.', '_', ':', '-'; must start with a letter; "
            "max 128 chars)"
        )
    return name


def _annotation_text(annotation: Any) -> str | None:
    if annotation is inspect.Parameter.empty:
        return None
    if isinstance(annotation, str):
        return annotation
    if isinstance(annotation, type):
        module = getattr(annotation, "__module__", None)
        qualname = getattr(annotation, "__qualname__", annotation.__name__)
        if module and module != "builtins":
            return f"{module}.{qualname}"
        return qualname
    # typing constructs (Optional[int], list[str], ...) have stable str() forms
    return str(annotation)


def _parameter_descriptors(func: Callable[..., Any]) -> tuple[ParameterDescriptor, ...]:
    try:
        signature = inspect.signature(func)
    except (TypeError, ValueError) as exc:
        raise ContractError(f"cannot inspect signature of {func!r}: {exc}") from exc
    return tuple(
        ParameterDescriptor(
            name=param.name,
            kind=param.kind.name,
            has_default=param.default is not inspect.Parameter.empty,
            annotation=_annotation_text(param.annotation),
        )
        for param in signature.parameters.values()
    )


def _code_fingerprint(func: Callable[..., Any]) -> str | None:
    try:
        source = inspect.getsource(func)
    except (OSError, TypeError):
        return None
    return sha256_hex(textwrap.dedent(source).encode("utf-8"))


def _build_contract_unchecked(
    func: Callable[..., Any],
    *,
    action: str | None,
    risk: str,
    approval: str,
) -> ActionContract:
    """Build the contract without async/generator rejection.

    ``wrap_tool`` validates callable categories itself and then calls this
    function so async callables can receive a valid evidence v1 contract
    without changing ``@guard``'s decoration-time rejection.
    """
    if risk not in RISK_LEVELS:
        raise ContractError(f"invalid risk {risk!r}: expected one of {RISK_LEVELS}")
    if approval not in APPROVAL_MODES:
        raise ContractError(f"invalid approval {approval!r}: expected one of {APPROVAL_MODES}")

    module = cast(str, getattr(func, "__module__", None) or "unknown")
    qualified_name = cast(
        str, getattr(func, "__qualname__", None) or getattr(func, "__name__", "unknown")
    )
    action_name = (
        validate_action_name(action) if action is not None else f"{module}.{qualified_name}"
    )

    descriptors = _parameter_descriptors(func)
    fingerprint = _code_fingerprint(func)

    unsigned = {
        "schema_version": CONTRACT_SCHEMA_VERSION,
        "action_name": action_name,
        "module": module,
        "qualified_name": qualified_name,
        "risk": risk,
        "approval_mode": approval,
        "execution_mode": EXECUTION_MODE_EMBEDDED,
        "parameter_descriptors": [dataclasses.asdict(d) for d in descriptors],
        "code_fingerprint": fingerprint,
    }
    contract_hash = sha256_hex(canonical_json_bytes(unsigned))

    return ActionContract(
        schema_version=CONTRACT_SCHEMA_VERSION,
        action_name=action_name,
        module=module,
        qualified_name=qualified_name,
        risk=risk,
        approval_mode=approval,
        execution_mode=EXECUTION_MODE_EMBEDDED,
        parameter_descriptors=descriptors,
        code_fingerprint=fingerprint,
        contract_hash=contract_hash,
    )


def build_contract(
    func: Callable[..., Any],
    *,
    action: str | None,
    risk: str,
    approval: str,
) -> ActionContract:
    """Build the deterministic action contract for a guarded function.

    Asynchronous functions are supported; ``@guard`` and ``wrap_tool`` build
    their contracts through this path. Generator and async-generator functions
    are rejected: guarding a generator would record an outcome before any work
    runs.
    """
    if inspect.isasyncgenfunction(func) or inspect.isgeneratorfunction(func):
        raise UnsupportedFunctionError(
            f"@guard does not support generator functions; "
            f"{getattr(func, '__qualname__', func)!r} yields instead of returning. "
            "Guarding a generator would record an outcome before any work runs."
        )
    return _build_contract_unchecked(func, action=action, risk=risk, approval=approval)
