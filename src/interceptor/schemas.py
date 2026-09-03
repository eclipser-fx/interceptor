"""Framework-neutral tool descriptions for guarded callables.

Agent frameworks (OpenAI function calling, MCP, LangChain) all need the same
thing: a name, a description, and a JSON Schema for the parameters. These
helpers derive it from :func:`inspect.signature` — on a plain or an already
guarded function (``functools.wraps`` preserves ``__wrapped__``, which
signature-following resolves) — so the schema can never disagree with the
contract the evidence commits to.
"""

from __future__ import annotations

import dataclasses
import inspect
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
        return _schema_for_name(text[len("Optional[") : -1])
    if "|" in text:  # "X | None"
        for part in text.split("|"):
            schema = _schema_for_name(part)
            if schema and schema != {"type": "null"}:
                return schema
        return {}
    for prefix, kind in (("list[", "array"), ("tuple[", "array"), ("dict[", "object")):
        if text.startswith(prefix):
            return {"type": kind}
    return {}


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
    if origin is Union:
        options = [_schema_for(arg) for arg in get_args(annotation) if arg is not type(None)]
        options = [opt for opt in options if opt]
        if len(options) == 1:
            return options[0]
        if options:
            return {"anyOf": options}
        return {}
    if origin in (list, tuple, set, frozenset):
        args = get_args(annotation)
        return {"type": "array", "items": _schema_for(args[0]) if args else {}}
    if origin is dict:
        return {"type": "object"}
    if isinstance(annotation, type) and dataclasses.is_dataclass(annotation):
        properties = {}
        for field in dataclasses.fields(annotation):
            properties[field.name] = _schema_for(field.type)
        return {"type": "object", "properties": properties}
    return {}


def describe_tool(func: Callable[..., Any]) -> dict[str, Any]:
    """``{"name", "description", "parameters"}`` for *func*.

    Raises :class:`ValueError` when the signature cannot be inspected.
    """
    name = getattr(func, "__name__", None) or "tool"
    description = (inspect.getdoc(func) or "").splitlines()[0] if inspect.getdoc(func) else ""
    try:
        signature = inspect.signature(func)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"cannot describe tool {name!r}: {exc}") from exc
    properties: dict[str, Any] = {}
    required: list[str] = []
    for param in signature.parameters.values():
        if param.kind in (param.VAR_POSITIONAL, param.VAR_KEYWORD):
            continue
        properties[param.name] = _schema_for(param.annotation)
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
