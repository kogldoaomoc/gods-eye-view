"""Adapter registry and the default routing table.

The registry lists every adapter the bridge knows. Adapters whose tool is a
broken or unmaintained project are marked ``legacy`` and stay off by default,
but are still listed with their health so nothing fails silently.
"""

from __future__ import annotations

from .base import READY, Adapter, AdapterError, Cancelled, RateLimited, Result, RunContext
from .maigret import MaigretAdapter
from .phoneinfoga import PhoneInfogaAdapter
from .sherlock import SherlockAdapter
from .spiderfoot import SpiderFootAdapter
from .theharvester import TheHarvesterAdapter

# Instantiated once; adapters hold no per-run state.
_ADAPTERS: tuple[Adapter, ...] = (
    SpiderFootAdapter(),
    TheHarvesterAdapter(),
    SherlockAdapter(),
    MaigretAdapter(),
    PhoneInfogaAdapter(),
)

REGISTRY: dict[str, Adapter] = {adapter.name: adapter for adapter in _ADAPTERS}

# Tools run for each selector type when the caller does not name a set. Legacy
# adapters are never a default; the user ticks them explicitly.
DEFAULT_ROUTING: dict[str, tuple[str, ...]] = {
    "username": ("maigret", "sherlock"),
    "email": ("theharvester",),
    "phone": ("phoneinfoga",),
    "domain": ("theharvester", "spiderfoot"),
    "host": ("spiderfoot",),
    "ip": ("spiderfoot",),
    "person": ("spiderfoot",),
    "organization": ("spiderfoot",),
    "address": ("spiderfoot",),
}


def get(name: str) -> Adapter:
    try:
        return REGISTRY[name]
    except KeyError:
        raise KeyError(f"unknown tool: {name!r}") from None


def default_tools(selector_type: str) -> list[str]:
    return [name for name in DEFAULT_ROUTING.get(selector_type, ()) if name in REGISTRY]


def tools_for(selector_type: str) -> list[str]:
    """Every registered tool that accepts this selector type."""
    return [name for name, adapter in REGISTRY.items() if selector_type in adapter.accepts]


def describe(env: dict | None = None) -> list[dict]:
    return [adapter.describe(env) for adapter in REGISTRY.values()]


__all__ = [
    "READY",
    "REGISTRY",
    "DEFAULT_ROUTING",
    "Adapter",
    "AdapterError",
    "Cancelled",
    "RateLimited",
    "Result",
    "RunContext",
    "get",
    "default_tools",
    "tools_for",
    "describe",
]
