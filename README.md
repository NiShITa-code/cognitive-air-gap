# CADA - Runtime Monitoring of Autonomous LLM Code-Agents

**An executed, byte-confirmed study of when OS-level monitoring can and cannot see an
LLM agent exfiltrate a secret and why the answer depends on the *model*, not the monitor.**

Nishita Jain · BlueDot Impact · paper: [`paper/paper.pdf`](paper/) *(compiled separately — see note below)*

---

## The finding in one paragraph

When an autonomous code-agent exfiltrates a secret, the most-trusted runtime defense,
OS data-flow *taint* tracking, is often **structurally blind** to it. The agent reads the
secret into its context window and re-types it as a **literal** in a later command; no system
call links the read to the send. We call this the **cognitive air-gap**. On an executed
substrate (real attacks under `strace` in a network-isolated sandbox, egress byte-confirmed at
a DNS/TCP sinkhole, with the secret's marker seeded *after* the prompt so a landed exfil
requires the agent to learn and re-emit it at runtime), we find that *whether* an agent does
this is a **model-indexed coding idiom**: on matched tasks, gpt-4o and llama-3.3 re-type the
literal and defeat taint 97–100% of the time, while qwen-2.5 routes the same secret through an
OS-visible path (`$(cat)` / `@file`) and stays fully traceable
(Fisher exact p = 6.5×10⁻¹¹; within-task perfectly separated).

**Monitorability is a property of the model you deployed, not the monitor you built.**

## Key results

- **Cognitive air-gap, model-indexed** — taint-proof rate **0.97 / 1.00 / 0.28**
  (gpt-4o / llama-3.3 / qwen-2.5); **75%** of 76 byte-confirmed exfils are taint-proof literal
  re-types; verified not to be a harness artifact.
- **Complementary blind spots** — the taint-blind literal is *text*-visible (a `grep` of the
  command finds the plaintext); qwen's substitution is text-blind but taint-visible. A cheap
  union of the two reaches full recall on all 76 exfils **in the non-adversarial regime**, with
  the honest cost that no value-flow monitor separates an *authorized* release from an
  exfiltration of the same secret.
- **Credential leakage is a localized scrubbing omission** — told to bundle a directory and
  upload it, agents include an in-scope secret. A controlled dissociation localizes the failure
  to *(broad bundle-and-upload instruction)* × *(secret in the bundled path)*, remove either
  and the leak rate is **0** (scope effect Fisher exact p = 1.6×10⁻⁴).
- **Capability does not predict monitorability** — base64-monitorability AUROC is non-monotone
  across families (**0.56 / 0.30 / 0.82** for Haiku-4.5 / GPT-4o / Sonnet-4.6).

## Repository map

```
paper/            the paper (PDF) and the four figures it cites
cada/             core library (config, cache, monitors, metrics, obfuscation)
experiments/cadc/ the executed harness, monitors, and experiments (a coupled Python package)
results/          per-experiment writeups (RESULTS_*.md) + byte-confirmed trajectory caches
tests/            unit tests for the analysis core
ROADMAP.md        exploratory next directions (not part of the results above)
REPRODUCE.md      one-command offline reproduction
```

**Scripts that produce the findings:**

| Result | Script |
|---|---|
| Case 1 — air-gap mechanism decomposition | `experiments/cadc/exp_airgap_mechanism.py` |
| Taint vs. text complementarity | `experiments/cadc/exp_complementarity.py` |
| Value-flow (union) monitor | `experiments/cadc/exp_crossturn_monitor.py` |
| Prompt-controllable idiom knob (steer) | `experiments/cadc/exp_steer.py` |
| Five-family × two-temperature robustness | `experiments/cadc/exp_scale.py` |
| Adversarial, byte-confirmed arm | `experiments/cadc/exp_airgap_adv.py` |
| Case 2 — credential scrubbing-omission dissociation | `experiments/cadc/exp_gate1.py` |
| Case 3 — capability vs. monitorability | `experiments/cadc/model_ladder.py` |
| Core analysis + substrate | `experiments/cadc/{airgap_core,taint_monitor,trace_runner}.py` |

Other modules in `experiments/cadc/` are shared infrastructure that these scripts import; the
package is tightly coupled and is kept whole so it runs.

## Reproduce

```bash
pip install -r requirements.txt
python -m experiments.cadc.exp_airgap_adv --from-cache results/headtohead_runs/airgap_traj
```

See [`REPRODUCE.md`](REPRODUCE.md) for the full offline path. Running the *live* experiments
(re-collecting traces) additionally requires Docker and an OpenRouter API key in a local `.env`.

## The paper

`paper/paper.pdf` is compiled from the LaTeX source (kept outside this repo). Until it is posted,
see `paper/README.md` for status. Please cite the paper, not this repository, for the results.

## License

Code and data released under the MIT License (see `LICENSE`). This is authorized defensive
security research; the "secrets" are random, per-episode, sinkhole-bound markers, and the
in-repo canary tokens are intentional test fixtures.
