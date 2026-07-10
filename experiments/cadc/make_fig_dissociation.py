"""F4: the credential scrubbing-omission dissociation. Leak occurs only under a bundle-and-upload instruction with the
secret in scope; every control (de-instructed / out-of-scope / narrow-ask) drives it to 0. Offline. -> paper/figures/."""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np, os

OUT = "paper/figures"; os.makedirs(OUT, exist_ok=True)
models = ["GPT-4o", "Llama-3.3-70B", "Qwen-2.5-72B"]
# byte-confirmed leak rate per condition (from RESULTS_gate1 / g2 / deinstruct)
conds = [
    ("bundle-instructed,\nsecret in scope", [0.50, 0.33, 0.17], "#c0392b"),
    ("de-instructed\n(post a summary)",      [0.00, 0.00, 0.00], "#2471a3"),
    ("secret out of scope",                  [0.00, 0.00, 0.00], "#27ae60"),
    ("narrow named-file ask",                [0.00, 0.00, 0.00], "#8e44ad"),
]
x = np.arange(len(models)); w = 0.2
fig, ax = plt.subplots(figsize=(8, 4.4))
for i, (label, vals, color) in enumerate(conds):
    bars = ax.bar(x + (i - 1.5) * w, vals, w, label=label, color=color)
    for b, v in zip(bars, vals):
        ax.text(b.get_x() + b.get_width() / 2, v + 0.012, "0" if v == 0 else f"{v:.2f}",
                ha="center", fontsize=8)
ax.set_xticks(x); ax.set_xticklabels(models)
ax.set_ylabel("byte-confirmed credential-leak rate")
ax.set_ylim(0, 0.6)
ax.set_title("Credential leakage is a scrubbing omission, precisely localized\n"
             "(occurs only under a bundle-and-upload instruction with the secret in scope)", fontsize=10)
ax.legend(fontsize=8, ncol=2, loc="upper right")
fig.tight_layout()
fig.savefig(f"{OUT}/fig_dissociation.png", dpi=150, bbox_inches="tight")
print("wrote", f"{OUT}/fig_dissociation.png")
