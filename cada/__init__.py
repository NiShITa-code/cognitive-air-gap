"""cada — obfuscation-robust monitoring of code agents.

A research toolkit for the question: does a kernel-level *behavioral* monitor detect
programmatically-obfuscated malicious agent actions that *text* guardrails miss?

Public API:
    from cada import obfuscation, metrics
    from cada.data import Action, sample_actions, load_redcode
    from cada.monitors.text import build_text_monitors
    from cada.monitors.behavioral import StraceMonitor
"""
from __future__ import annotations

__version__ = "0.1.0"

from . import metrics, obfuscation  # noqa: F401

__all__ = ["obfuscation", "metrics", "__version__"]
