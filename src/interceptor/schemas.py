"""Framework-neutral tool descriptions for guarded callables.

Agent frameworks (OpenAI function calling, MCP, LangChain) all need the same
thing: a name, a description, and a JSON Schema for the parameters. These
helpers derive it from :func:`inspect.signature` — on a plain or an already
guarded function (``functools.wraps`` preserves ``__wrapped__``, which
signature-following resolves) — so the schema tracks the contract the
evidence commits to. Where JSON Schema cannot express a Python construct
exactly (see below), the schema says so explicitly instead of silently lying:

* ``*args`` maps to ``{"type": "array"}`` and ``**kwargs`` to
  ``{"type": "object"}`` — variadics are accepted by call binding, so they are
  described, never dropped;
* ``X | None`` / ``Optional[X]`` maps to ``{"anyOf": [<X>, {"type": "null"}]}``
  so explicit ``null`` validates;
* dataclass fields without defaults are listed in ``required``;
* anything else unresolvable maps to ``{}`` (unconstrained), never to a
  narrower type than the annotation allows.
"""

from __future__ import annotations

import dataclasses
import inspect
import types
from collections.abc import Callable
from typing import Any, Union, get_args, get_origin

_SIMPLE_TYPES: dict[Any, str] = {
    str: "string",
    int: "integer",
    float: "number",
    bool: "boolean",
    list: "array",
    dict: "object",
}

_NAME_TYPES: dict[str, str] = {
    "str": "string",
    "int": "integer",
    "float": "number",
    "bool": "boolean",
    "list": "array",
    "dict": "object",
    "None": "null",
    "NoneType": "null",
}


def _schema_for_name(name: str) -> dict[str, Any]:
    """JSON Schema for a string annotation (PEP 563 postpones these to strings)."""
    text = name.strip().strip("'\"")
    if text in _NAME_TYPES:
        return {"type": _NAME_TYPES[text]}
    if text.startswith("Optional[") and text.endswith("]"):
        return _with_null(_schema_for_name(text[len("Optional[") : -1]))
    if "|" in text:  # "X | None"
        parts = [_schema_for_name(part) for part in text.split("|")]
        non_null = [schema for schema in parts if schema and schema != {"type": "null"}]
        nullable = len(non_null) != len([p for p in parts if p])
        if not non_null:
            return {"type": "null"} if nullable else {}
        if len(non_null) == 1:
            return _with_null(non_null[0]) if nullable else non_null[0]
        return {"anyOf": [*non_null, {"type": "null"}]} if nullable else {"anyOf": non_null}
    for prefix, kind in (("list[", "array"), ("tuple[", "array"), ("dict[", "object")):
        if text.startswith(prefix):
            return {"type": kind}
    return {}


def _with_null(schema: dict[str, Any]) -> dict[str, Any]:
    """Add explicit nullability, preserving unconstrained as unconstrained."""
    if not schema:
        return {}
    if schema == {"type": "null"}:
        return schema
    return {"anyOf": [schema, {"type": "null"}]}


def _schema_for(annotation: Any) -> dict[str, Any]:
    """Best-effort JSON Schema for one annotation; ``{}`` means unconstrained."""
    if isinstance(annotation, str):
        return _schema_for_name(annotation)
    if annotation is inspect.Parameter.empty:
        return {}
    if annotation in _SIMPLE_TYPES:
        return {"type": _SIMPLE_TYPES[annotation]}
    if annotation is None or annotation is type(None):
        return {"type": "null"}
    origin = get_origin(annotation)
    if origin is Union or origin is types.UnionType:
        args = get_args(annotation)
        nullable = type(None) in args
        options = [_schema_for(arg) for arg in args if arg is not type(None)]
        options = [opt for opt in options if opt]
        if not options:
            return {"type": "null"} if nullable else {}
        if len(options) == 1:
            return _with_null(options[0]) if nullable else options[0]
        return {"anyOf": [*options, {"type": "null"}]} if nullable else {"anyOf": options}
    if origin in (list, tuple, set, frozenset):
        args = get_args(annotation)
        return {"type": "array", "items": _schema_for(args[0]) if args else {}}
    if origin is dict:
        return {"type": "object"}
    if isinstance(annotation, type) and dataclasses.is_dataclass(annotation):
        try:
            import typing as _typing

            field_hints = _typing.get_type_hints(annotation)
        except Exception:
            field_hints = {}
        properties = {}
        required = []
        for field in dataclasses.fields(annotation):
            properties[field.name] = _schema_for(field_hints.get(field.name, field.type))
            if (
                field.default is dataclasses.MISSING
                and field.default_factory is dataclasses.MISSING
            ):
                required.append(field.name)
        schema: dict[str, Any] = {"type": "object", "properties": properties}
        if required:
            schema["required"] = required
        return schema
    return {}


def describe_tool(func: Callable[..., Any]) -> dict[str, Any]:
    """``{"name", "description", "parameters"}`` for *func*.

    String annotations are resolved with :func:`typing.get_type_hints` where
    possible (so nested dataclasses and real unions describe faithfully);
    unresolvable names fall back to their string form. Raises
    :class:`ValueError` when the signature cannot be inspected.
    """
    name = getattr(func, "__name__", None) or "tool"
    description = (inspect.getdoc(func) or "").splitlines()[0] if inspect.getdoc(func) else ""
    try:
        signature = inspect.signature(func)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"cannot describe tool {name!r}: {exc}") from exc
    try:
        import typing as _typing

        hints = _typing.get_type_hints(func)
    except Exception:
        hints = {}
    properties: dict[str, Any] = {}
    required: list[str] = []
    for param in signature.parameters.values():
        annotation = hints.get(param.name, param.annotation)
        if param.kind is param.VAR_POSITIONAL:
            properties[param.name] = {"type": "array"}
            continue
        if param.kind is param.VAR_KEYWORD:
            properties[param.name] = {"type": "object"}
            continue
        properties[param.name] = _schema_for(annotation)
        if param.default is param.empty:
            required.append(param.name)
    return {
        "name": name,
        "description": description,
        "parameters": {
            "type": "object",
            "properties": properties,
            "required": required,
        },
    }


def as_openai_tool(
    func: Callable[..., Any], *, name: str | None = None, description: str | None = None
) -> dict[str, Any]:
    """An OpenAI function-calling ``{"type": "function", ...}`` tool definition."""
    schema = describe_tool(func)
    tool_name = name or schema["name"]
    return {
        "type": "function",
        "function": {
            "name": tool_name,
            "description": description if description is not None else schema["description"],
            "parameters": schema["parameters"],
        },
    }


def mcp_tool(server: Any, func: Callable[..., Any], *, name: str | None = None) -> Any:
    """Register *func* on an MCP server object with a ``.tool()`` decorator.

    Works with ``mcp.server.fastmcp.FastMCP`` (or any compatible object) without
    taking a dependency on it: only the server you pass needs the package.
    The registered function keeps its guard — calling through MCP still
    records decision/outcome evidence when *func* is guarded.
    """
    schema = describe_tool(func)
    tool_name = name or schema["name"]
    return server.tool(name=tool_name, description=schema["description"])(func)
