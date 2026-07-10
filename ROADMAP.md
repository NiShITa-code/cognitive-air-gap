# Roadmap — exploratory next directions

These are **in-progress / candidate** directions, not established results. They are listed for
transparency; none of the claims below are supported by the executed measurements in this repo.

## Hardening the current paper
- **Diverse-benign false-positive battery.** The intent-blindness false-positive figure is
  currently measured against a single authorized-release template. A varied authorized-release
  corpus (across secret types and allowlisted destinations) would turn it into a claim over a
  distribution.
- **Persistent-shell harness ablation.** The "not a harness artifact" argument is partly
  conditioned on the fresh-shell-per-command scaffold; a persistent-shell harness would test
  whether agents use a `$VAR` carrier that a session-level monitor could catch.
- **Seeds / CIs** on the between-model rankings to move them from directional to significant.

## Larger open questions (design-stage)
- **Reasoning-channel vs. action-channel monitoring.** When does monitoring an agent's
  reasoning beat monitoring its actions, given that authorization is exogenous to the agent's
  computation? (Related: the 2025 chain-of-thought-monitorability line.)
- **Latent / context-window information-flow tracking.** Whether the read→send join — invisible
  at the OS layer — is recoverable inside the model (activations), and at what false-positive
  cost. Requires open weights + GPU; gated on first demonstrating that transform-in-context
  exfils (which the current cheap monitors would miss) actually occur.
- **Multi-agent / inter-agent air-gap.** Whether the read and the send can be split across two
  agents' traces, and how monitorability depends on agent topology and the model mix. The
  runtime/OS-substrate version of this appears under-explored; a candidate second study.

Each direction will be pre-registered and adversarially reviewed before any spend, consistent
with the methodology used for the results in this repo.
