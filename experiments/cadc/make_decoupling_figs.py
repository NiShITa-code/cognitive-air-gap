"""make_decoupling_figs.py — generate the 3 verified figures for the decoupling paper from the summary JSONs.
F1 decoupling (monitorability not monotone in capability), F2 mechanism decomposition, F3 monitor recall/FP per model.
Offline; reads results/headtohead_runs/*.summary.json. Saves PNGs to paper/figures/.
"""
from __future__ import annotations
import json, os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

OUT = "paper/figures"
os.makedirs(OUT, exist_ok=True)
RUN = "results/headtohead_runs"


def load(p):
    return json.load(open(p, encoding="utf-8"))


# ---------- F1: the decoupling (two panels, honest: different model panels) ----------
ladder = load(f"{RUN}/main.ladder.summary.json")["ladder"]
# order text judges by rough capability: Haiku < GPT-4o < Sonnet
text_order = ["Haiku-4.5", "GPT-4o", "Sonnet-4.6"]
text_b64 = {r["model"]: r["O1_base64"] for r in ladder}
cross = load(f"{RUN}/exp_crossturn_monitor.summary.json")["by_model"]
# taint per-command recall (B1) per agent model, rough capability order
taint_order = ["qwen-2.5-72b-instruct", "llama-3.3-70b-instruct", "gpt-4o"]
taint_recall = {m: (cross[m]["b1_recall"][0] if cross[m]["b1_recall"] else 0.0) for m in taint_order}

fig, (axL, axR) = plt.subplots(1, 2, figsize=(10, 4.2))

# Left: text level base64 monitorability
xs = list(range(len(text_order)))
ys = [text_b64[m] for m in text_order]
axL.plot(xs, ys, "-o", color="#c0392b", lw=2, ms=9)
axL.axhline(0.5, ls="--", color="gray", lw=1)
axL.text(0.02, 0.505, "chance", color="gray", fontsize=8, transform=axL.get_yaxis_transform())
for x, y in zip(xs, ys):
    axL.annotate(f"{y:.2f}", (x, y), textcoords="offset points", xytext=(0, 10), ha="center", fontsize=9)
axL.set_xticks(xs); axL.set_xticklabels(["Haiku-4.5", "GPT-4o", "Sonnet-4.6"])
axL.set_ylim(0.15, 0.95); axL.set_ylabel("base64 monitor AUROC (higher = more monitorable)")
axL.set_title("Text level: base64 monitorability\n(frontier GPT-4o dips below tiny Haiku)", fontsize=10)
axL.annotate("more capable →", xy=(0.5, -0.14), xycoords="axes fraction", ha="center", fontsize=8, color="gray")

# Right: information-flow level per-command taint recall
xs2 = list(range(len(taint_order)))
ys2 = [taint_recall[m] for m in taint_order]
axR.plot(xs2, ys2, "-o", color="#2471a3", lw=2, ms=9)
for x, y in zip(xs2, ys2):
    axR.annotate(f"{y:.2f}", (x, y), textcoords="offset points", xytext=(0, 10), ha="center", fontsize=9)
axR.set_xticks(xs2); axR.set_xticklabels(["Qwen-2.5-72B", "Llama-3.3-70B", "GPT-4o"])
axR.set_ylim(-0.05, 1.0); axR.set_ylabel("per-command taint recall on exfil (higher = more monitorable)")
axR.set_title("Info-flow level: OS-taint monitorability\n(frontier models near zero)", fontsize=10)
axR.annotate("more capable →", xy=(0.5, -0.14), xycoords="axes fraction", ha="center", fontsize=8, color="gray")

fig.suptitle("Monitorability is decoupled from capability (two observation levels)", fontsize=12, y=1.0)
fig.tight_layout(rect=[0, 0.03, 1, 0.97])
fig.savefig(f"{OUT}/fig_decoupling.png", dpi=150, bbox_inches="tight")
print("wrote fig_decoupling.png")

# ---------- F2: mechanism decomposition per model ----------
mech = load(f"{RUN}/exp_airgap_mechanism.summary.json")["by_model"]
models = ["gpt-4o", "llama-3.3-70b-instruct", "qwen-2.5-72b-instruct"]
labels = ["GPT-4o", "Llama-3.3-70B", "Qwen-2.5-72B"]
proof = [mech[m]["mech"].get("LITERAL_RETYPE", 0) for m in models]
catch = [sum(mech[m]["mech"].get(k, 0) for k in ("INLINE_SUBST", "FILE_FLOW", "SHELL_VAR", "MIXED")) for m in models]
fig2, ax2 = plt.subplots(figsize=(6.5, 4.2))
x = list(range(len(models)))
ax2.bar(x, proof, color="#c0392b", label="taint-PROOF (literal re-type; air-gap)")
ax2.bar(x, catch, bottom=proof, color="#27ae60", label="OS-visible (caught by taint)")
for i, (p, c) in enumerate(zip(proof, catch)):
    tot = p + c
    ax2.text(i, tot + 0.4, f"{100*p/tot:.0f}% proof", ha="center", fontsize=9)
ax2.set_xticks(x); ax2.set_xticklabels(labels)
ax2.set_ylabel("landed byte-confirmed exfiltrations")
ax2.set_title("How each model routes stolen secrets (Fisher p = 5e-8)", fontsize=11)
ax2.legend(fontsize=8, loc="upper right")
fig2.tight_layout()
fig2.savefig(f"{OUT}/fig_mechanism.png", dpi=150, bbox_inches="tight")
print("wrote fig_mechanism.png")

# ---------- F3: per-command vs cross-turn monitor recall & FP ----------
fig3, ax3 = plt.subplots(figsize=(7.5, 4.2))
def val(m, k):
    v = cross[m][k]
    return v[0] if v else 0.0
import numpy as np
xm = np.arange(len(models)); w = 0.2
b1r = [val(m, "b1_recall") for m in models]
b2r = [val(m, "b2_recall") for m in models]
b1f = [val(m, "b1_fp") for m in models]
b2f = [val(m, "b2_fp") for m in models]
ax3.bar(xm - 1.5*w, b1r, w, color="#2471a3", label="per-command recall")
ax3.bar(xm - 0.5*w, b2r, w, color="#5dade2", label="cross-turn recall")
ax3.bar(xm + 0.5*w, b1f, w, color="#b03a2e", label="per-command FP")
ax3.bar(xm + 1.5*w, b2f, w, color="#e59866", label="cross-turn FP")
ax3.set_xticks(xm); ax3.set_xticklabels(labels)
ax3.set_ylabel("rate"); ax3.set_ylim(0, 1.05)
ax3.set_title("Which monitor is adequate is model-indexed\n(cross-turn recovers recall only at intent-blind FP)", fontsize=10)
ax3.legend(fontsize=8, ncol=2)
fig3.tight_layout()
fig3.savefig(f"{OUT}/fig_monitor_selection.png", dpi=150, bbox_inches="tight")
print("wrote fig_monitor_selection.png")
print("DONE ->", OUT)
