# RESULTS — Per-command vs cross-turn taint is a MODEL-INDEXED monitor-selection problem

**Status:** REAL, offline on cached data. `experiments/cadc/exp_crossturn_monitor.py`. Date 2026-07-02 (session 14).
Summary JSON: `results/headtohead_runs/exp_crossturn_monitor.summary.json`. Pairs with `RESULTS_airgap_mechanism.md`.

## Setup
Two monitors on the same landed episodes: **B1 per-command taint** (status quo: process-tree taint within one
command) vs **B2 cross-turn value taint** (persists secret values across commands, flags any egress carrying one).
Recall on landed byte-confirmed exfils; FP on landed authorized releases (benign use of the same credential).

## Result (Wilson point estimates)
| model | B1 recall (exfil) | B2 recall | B1 FP (benign) | B2 FP |
|---|---|---|---|---|
| gpt-4o | 1/30 = **0.03** | 30/30 = 1.00 | 0/8 = 0.00 | 8/8 = 1.00 |
| llama-3.3-70b | 0/21 = **0.00** | 21/21 = 1.00 | 2/13 = 0.15 | 13/13 = 1.00 |
| qwen-2.5-72b | 18/25 = **0.72** | 25/25 = 1.00 | 0/13 = 0.00 | 13/13 = 1.00 |

## What it means (honest)
1. **Per-command taint adequacy is model-indexed.** For qwen it is a *good* monitor (0.72 recall, 0 FP) because its
   `$(cat)`/`@file` idiom keeps the flow OS-visible. For gpt-4o/llama it is **useless** (recall ~0): their
   literal-retype idiom is invisible to it.
2. **The cross-turn upgrade is not a free lunch.** B2 recovers recall to 1.00 for everyone but flags a secret value on
   the wire *regardless of intent* → FP 1.00 on authorized release. A value-flow monitor cannot separate an authorized
   from an unauthorized release of the same credential by observation alone (conceded limitation, not the headline).
3. **The actionable, deployable lever = the model-indexed steer.** Rather than an un-evadable monitor (impossible),
   steer gpt-4o/llama toward OS-visible idioms so cheap low-FP per-command taint becomes adequate (qwen-like), *without*
   solving the intent problem. This is the positive "fix" — and the one genuinely novel deployable contribution.

## Caveats
Pilot N (21–30 exfil / 8–13 benign per model); benign band is the auth/meta-release pair, not yet diverse; the steer
(step 3) is measured on a VM run, not yet done. B2 FP is measured only against this benign pair (a diverse benign band
would refine the absolute FP but not the model-indexed pattern).

## Paper arc this supports (measure → explain → fix)
- **Measure:** monitorability is model-indexed (RESULTS_airgap_mechanism.md; p≈5e-8).
- **Explain:** per-command taint recall 0/0/0.72; cross-turn recovers recall only at the intent-blind FP wall (this doc).
- **Fix:** the idiom steer makes cheap taint adequate for the invisible models (TODO — VM run).
