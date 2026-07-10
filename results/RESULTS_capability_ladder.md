# Tier-2: the decoding arms race as a capability law (model ladder)

**Date:** 2026-06-18. **Script:** `experiments/cadc/model_ladder.py` (API-only). **Bottom rung:** 880 Haiku-4.5
calls, 0 refusals, cache `main.haiku_cache.json`. **Other rungs reuse existing data** (GPT-4o = `main.jsonl`,
Sonnet-4.6 = `main.claude.jsonl`). **Summary:** `main.ladder.summary.json`. Same graded prompt + commands throughout.

## Question
Is representational robustness bounded by the monitor's *decoding ability*? If so, judge AUROC on a **decodable**
encoding (base64) should rise with model capability, while AUROC on a **non-decodable** encoding (XOR) should stay
flat across the whole capability range.

## Result — judge AUROC

| judge | clean | base64 | XOR |
|---|---|---|---|
| **Haiku-4.5** (small) | 0.80 | 0.56 | 0.76 |
| GPT-4o (cross-family ref.) | 0.81 | 0.30 | 0.74 |
| **Sonnet-4.6** (frontier) | 0.85 | 0.82 | 0.74 |

Haiku-4.5 ↔ Sonnet-4.6 = controlled **within-family** capability pair; GPT-4o = cross-family reference.

## Findings (honest)
1. **base64 resistance is bought by capability — within family.** Haiku-4.5 0.56 → Sonnet-4.6 0.82. Base64
   resistance *is* a decoding capability.
2. **The cross-family point is non-monotone** (GPT-4o 0.30 < Haiku 0.56). GPT-4o fails *worse* not from lower
   capability but from the strongest base64→malware **prior** (it flags the wrapper hardest). The failure mode for
   weaker/poorly-primed judges is a prior, not raw incapacity — so "monotone capability law" would be an overclaim;
   the honest claim is "the frontier resists base64, weaker models fail (idiosyncratically)."
3. **XOR is flat across the entire ladder (0.76 / 0.74 / 0.74).** The frontier's decoding advantage gives **zero**
   lift on XOR — Sonnet-4.6 is no better than Haiku-4.5. **Capability buys resistance only to encodings within the
   model's decode set.**

## Why it matters
Together with the prompt-lever ablation (`RESULTS_ablation_judgeprompt.md`), the arms race is now demonstrated from
**three** angles — a stronger model (Sonnet vs GPT-4o/Haiku), a stronger prompt (steelman vs original), and a
capability ladder — all converging on the same law: **the representation-level monitor's robustness equals its
decoding ability; the adversary picks an encoding outside it (XOR), where no model or prompt helps.** The
effect-level monitor opts out of the race (reads post-decode syscalls) at the cost of the FP-tax and semantic blind
spot (§5.3, §5.8).
