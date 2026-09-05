"""A single choke point for agent tool invocation.

The ``@guard`` decorator is a convention enforced at the call site: nothing
stops same-process code from calling the unguarded function directly. A
:class:`ToolGateway` closes the organizational half of that gap — agents invoke
tools only by name through :meth:`ToolGateway.invoke`, unknown names are denied,
and (by default) only guarded callables may be registered, so adding an
unguarded tool is a loud registration error instead of a silent bypass.

This is not a sandbox (a compromised process can still reach past it), but it
turns "someone wired a raw tool into the agent" from an invisible mistake into
a rejected deploy. Pair it with MCP serving (``mcp_tool`` registers the same
guarded callables) so remote agents face the same choke point.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from .errors import ActionDenied, ToolWrapError
from .wrap_tool import _CONTRACT_ATTR


class ToolGateway:
    """Name-routed invocation over guarded callables."""

    def __init__(self, *, require_guarded: bool = True) -> None:
        self._require_guarded = require_guarded
        self._tools: dict[str, Callable[..., Any]] = {}

    def register(self, name: str, func: Callable[..., Any]) -> Callable[..., Any]:
        """Register *func* under *name*. Returns *func* for decorator use."""
        if not name or not isinstance(name, str):
            raise ToolWrapError("tool gateway names must be non-empty strings")
        if name in self._tools:
            raise ToolWrapError(f"tool gateway already has a tool named {name!r}")
        if not callable(func):
            raise ToolWrapError(
                f"tool gateway entry {name!r} is not callable: {type(func).__name__}"
            )
        if self._require_guarded and not hasattr(func, _CONTRACT_ATTR):
            raise ToolWrapError(
                f"tool gateway entry {name!r} is not guarded; wrap it with @guard or "
                "wrap_tool first, or pass require_guarded=False to opt out"
            )
        self._tools[name] = func
        return func

    def names(self) -> tuple[str, ...]:
        """Registered tool names, in registration order."""
        return tuple(self._tools)

    def __contains__(self, name: object) -> bool:
        return name in self._tools

    def invoke(self, name: str, *args: Any, **kwargs: Any) -> Any:
        """Invoke the tool registered as *name* (sync or async passthrough).

        Unknown names raise :class:`ActionDenied` without executing anything.
        Async tools return a coroutine for the caller to await.
        """
        try:
            func = self._tools[name]
        except KeyError:
            raise ActionDenied(name, f"unknown tool {name!r}; denied") from None
        return func(*args, **kwargs)

    @classmethod
    def from_mapping(
        cls,
        tools: Mapping[str, Callable[..., Any]],
        *,
        require_guarded: bool = True,
    ) -> ToolGateway:
        """Build a gateway from a name-to-callable mapping."""
        gateway = cls(require_guarded=require_guarded)
        for name, func in tools.items():
            gateway.register(name, func)
        return gateway
