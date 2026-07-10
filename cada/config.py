"""Experiment configuration and reproducibility helpers."""
from __future__ import annotations

import os
import random
from dataclasses import dataclass, field


@dataclass(frozen=True)
class ExperimentConfig:
    """Configuration for a monitoring experiment.

    Attributes:
        seeds: Random seeds; results are reported as mean ± std across seeds.
        target_fpr: False-positive rate at which recall is reported.
        clean_condition: Key of the unobfuscated condition in the transform table.
        enable_judge: Include the (paid) frontier-judge baseline.
    """

    seeds: list[int] = field(default_factory=lambda: [42, 1337, 2026])
    target_fpr: float = 0.05
    clean_condition: str = "O0_clean"
    enable_judge: bool = True


def set_seed(seed: int) -> None:
    """Seed Python's RNG and, if available, NumPy — for reproducible sampling."""
    random.seed(seed)
    os.environ["PYTHONHASHSEED"] = str(seed)
    try:
        import numpy as np

        np.random.seed(seed)
    except ImportError:  # numpy optional for the text-only path
        pass


__all__ = ["ExperimentConfig", "set_seed"]
