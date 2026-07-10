"""Persistent JSON cache for LLM responses.

Used by gate scripts so a re-run after a crash doesn't re-pay for the calls
that already succeeded. Key is SHA256 of (model, messages, max_tokens). Value
is the raw response content string, or the sentinel ``__REFUSAL__`` for
provider-side content-filter refusals.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

REFUSAL = "__REFUSAL__"


class JsonCache:
    """File-backed dict; flushes on every set so a crash mid-run is recoverable."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.store: dict[str, str] = (
            json.loads(self.path.read_text()) if self.path.exists() else {}
        )

    def key(self, model: str, prompt: str, prefix: str = "") -> str:
        raw = json.dumps({"p": prefix, "m": model, "x": prompt}, sort_keys=True)
        return hashlib.sha256(raw.encode()).hexdigest()

    def get(self, key: str) -> str | None:
        return self.store.get(key)

    def set(self, key: str, value: str) -> None:
        self.store[key] = value
        self.path.write_text(json.dumps(self.store))

    def __len__(self) -> int:
        return len(self.store)


__all__ = ["JsonCache", "REFUSAL"]
