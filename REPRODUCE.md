# Reproduction

Every headline number can be re-derived **offline**, from the committed byte-confirmed traces,
with **no API calls and no GPU**.

## Setup
```bash
pip install -r requirements.txt
# run from the repository root so the `experiments.cadc` package resolves
```

## Offline (from cached traces)
```bash
# Case 1 — adversarial air-gap arm (byte-confirmed exfils), from cache
#   (verified: reproduces 250 episodes, 0 errors, 47/47 context-cross, taint 0/47)
python -m experiments.cadc.exp_airgap_adv --from-cache results/headtohead_runs/airgap_traj

# Case 1 — mechanism decomposition (taint-proof share, model split)
python -m experiments.cadc.exp_airgap_mechanism --from-cache results/headtohead_runs/airgap_traj

# Complementarity (taint vs. text) and the value-flow union monitor
python -m experiments.cadc.exp_complementarity
python -m experiments.cadc.exp_crossturn_monitor

# Five-family x two-temperature robustness, and the idiom steer
python -m experiments.cadc.exp_scale --from-cache
python -m experiments.cadc.exp_steer --from-cache

# Case 2 — credential scrubbing-omission dissociation
python -m experiments.cadc.exp_gate1 --from-cache
```
The cached inputs live in `results/headtohead_runs/` (summary JSONs + the
`airgap_traj/`, `airgap_xmodel/`, `ar_full/` per-episode trajectory directories). The written
analyses these reproduce are in `results/RESULTS_*.md`.

> Note: the exact `--from-cache` flag names may differ per script; run a script with `-h` to see
> its options. Some scripts print their summary JSON path on completion.

## Live (re-collecting traces — optional)
Running the experiments live additionally requires:
- **Docker** (each agent action runs under `strace` in a network-isolated container with a
  DNS/TCP sinkhole),
- an **OpenRouter API key** in a local `.env` at the repo root (never committed):
  ```
  OPENROUTER_API_KEY=...
  ```

## Tests
```bash
python -m pytest tests/
```
