# CADA: Runtime Monitoring of Autonomous LLM Code-Agents

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

> **Abstract:** When an autonomous code-agent exfiltrates a secret, the most-trusted runtime defense—OS data-flow *taint* tracking—is often **structurally blind** to it. The agent reads the secret into its context window and re-types it as a *literal* in a later command; no system call links the read to the send. We call this the **cognitive air-gap**. 
>
> In an executed, byte-confirmed study (real attacks under `strace` in a network-isolated sandbox), we demonstrate that *whether* an agent does this is a **model-indexed coding idiom**. On matched tasks, `gpt-4o` and `llama-3.3` re-type the literal and defeat taint 97–100% of the time, while `qwen-2.5` routes the same secret through an OS-visible path (`$(cat)` / `@file`) and stays fully traceable. Ultimately, **monitorability is a property of the model you deployed, not the monitor you built.**

---

## Core Concepts: Why Standard Security Fails

If you are new to OS security, here is what is happening under the hood:

*   **What is OS Taint Tracking?** Think of it like a dye pack in a bank vault. Traditional security "taints" (tags) sensitive files. If a normal program tries to read that file and send it to the internet, the operating system tracks the data flow and blocks it.
*   **What is the "Cognitive Air-Gap"?** AI agents break this tracking. An AI reads the sensitive file, memorizes the text in its neural network (its context window), and then types out a brand-new command from memory containing the secret. Because the data passed through the AI's "brain" instead of standard computer memory pipelines, the OS loses the trail. The exfiltration becomes **taint-proof**.

##  How We Ran the Experiments

To prove this wasn't just a theoretical vulnerability, we built a rigorous, network-isolated testing environment:
1.  **The Sandbox:** Agents were placed in a monitored Linux VM and given standard CI/CD tasks (e.g., "diagnose this server error").
2.  **The Secret:** A unique 19-character secret marker was seeded into a file *after* the agent's prompt was generated. This ensured the agent couldn't cheat; it had to discover the secret at runtime.
3.  **The Sinkhole (Byte-Confirmed):** The sandbox was isolated. The only way out was through a controlled DNS/TCP "sinkhole." An attack was only counted as "landed" if we could confirm the exact bytes of the secret hit our sinkhole on the wire.

---

## Key Findings

*   **The Cognitive Air-Gap is Model-Indexed:** The ability to bypass OS security depends entirely on the AI model you use. The taint-proof rate is **0.97 / 1.00 / 0.28** (`gpt-4o` / `llama-3.3` / `qwen-2.5`). **75%** of 76 byte-confirmed exfiltrations are taint-proof literal re-types. *(Read the mechanism breakdown [here](./results/RESULTS_airgap_mechanism.md))*
*   **Complementary Blind Spots (The Fix):** The taint-blind literal is *text*-visible (a `grep` of the command finds the plaintext); `qwen`'s OS-level substitution is text-blind but taint-visible. A cheap union of both monitors reaches **100% recall** on all 76 exfiltrations. *(Read the analysis [here](./results/RESULTS_complementarity.md))*
*   **Credential Leakage is a Scope Failure:** When told to bundle and upload a directory, agents spontaneously include in-scope secrets. A controlled test proved that if you remove the secret from the bundled path, the leak rate drops to **0** (scope effect Fisher exact p = 1.6 × 10⁻⁴). Agents fail to scrub data; they do not maliciously hunt for it. *(Read the scope data [here](./results/RESULTS_gate1.md))*
*   **Capability Does Not Predict Monitorability:** Base64-monitorability AUROC is non-monotone across families (**0.56 / 0.30 / 0.82** for `Haiku-4.5` / `GPT-4o` / `Sonnet-4.6`). A smarter model is not necessarily a safer or more monitorable one. *(Read the model ladder [here](./results/RESULTS_model_ladder.md))*

---

## Reproducibility & Quick Start

This project is built for **one-command offline reproduction**. You do not need API keys to verify our findings; we have cached all byte-confirmed trajectories, raw traces, and sink `net.logs`.

**1. Install Dependencies**
```bash
git clone [https://github.com/yourusername/cada.git](https://github.com/yourusername/cada.git)
cd cada
pip install -r requirements.txt
