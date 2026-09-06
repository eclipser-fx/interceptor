"""Schema fidelity: the framework description must match the contract."""

from __future__ import annotations

import dataclasses
from typing import Optional, Union

from interceptor.schemas import as_openai_tool, describe_tool


@dataclasses.dataclass
class Item:
    sku: str
    quantity: int = 1


@dataclasses.dataclass
class Order:
    item: Item
    rush: bool = False


def test_nullable_keeps_null() -> None:
    def act(note: str | None = None) -> None:
        return None

    assert describe_tool(act)["parameters"]["properties"]["note"] == {
        "anyOf": [{"type": "string"}, {"type": "null"}]
    }

    def old(note: Optional[str] = None) -> None:  # noqa: UP045 — legacy spelling under test
        return None

    assert describe_tool(old)["parameters"]["properties"]["note"] == {
        "anyOf": [{"type": "string"}, {"type": "null"}]
    }


def test_union_without_none_has_no_null() -> None:
    def act(value: Union[int, str]) -> None:  # noqa: UP007 — legacy spelling under test
        return None

    assert describe_tool(act)["parameters"]["properties"]["value"] == {
        "anyOf": [{"type": "integer"}, {"type": "string"}]
    }


def test_variadics_are_described_not_dropped() -> None:
    def act(first: str, *rest: int, **opts: str) -> None:
        return None

    properties = describe_tool(act)["parameters"]["properties"]
    assert properties["rest"] == {"type": "array"}
    assert properties["opts"] == {"type": "object"}
    assert describe_tool(act)["parameters"]["required"] == ["first"]


def test_nested_dataclass_requiredness() -> None:
    def act(order: Order) -> None:
        return None

    schema = describe_tool(act)["parameters"]["properties"]["order"]
    assert schema["type"] == "object"
    assert schema["required"] == ["item"]
    assert schema["properties"]["item"]["required"] == ["sku"]
    assert schema["properties"]["item"]["properties"]["quantity"] == {"type": "integer"}


def test_unresolvable_stays_unconstrained() -> None:
    def act(thing: "DoesNotExistAtRuntime") -> None:  # noqa: F821, UP037 — unresolvable by design
        return None

    assert describe_tool(act)["parameters"]["properties"]["thing"] == {}


def test_openai_shape_still_holds() -> None:
    def refund(customer_id: str, amount_cents: int) -> dict:
        """Refund a customer."""
        return {}

    tool = as_openai_tool(refund)
    assert tool["type"] == "function"
    assert tool["function"]["parameters"]["required"] == ["customer_id", "amount_cents"]
