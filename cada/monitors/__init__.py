"""Monitors: text-level guardrails and behavioural (syscall) monitors.

A *monitor* exposes ``predict(action: str) -> int`` returning ``1`` (flag as unsafe)
or ``0`` (allow), and a ``name`` attribute used as the row key in result tables.
"""
from __future__ import annotations

from typing import Protocol


class Monitor(Protocol):
    name: str

    def predict(self, action: str) -> int:  # pragma: no cover - interface only
        ...


__all__ = ["Monitor"]
