"""Build a genuine DATA-SCIENCE AGENT benign corpus from real Jupyter notebooks' shell cells.

Unlike build_ds_benign (CI run-steps from DS repos), this extracts the `!`-prefixed shell commands a
data scientist / agent actually runs INSIDE notebooks — dataset downloads (`!wget`/`!curl`/`!kaggle`),
installs (`!pip`), unzips, file ops. These are the closest mechanical proxy to autonomous DS-agent
actions, and they egress (download data) far more than CI — the strongest cross-domain FP-tax test.

Provenance-tagged, verbatim. Writes data/benign_ds_agent_corpus.json. Run on a host with network+git.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

SRC = Path("data/benign_sources_dsagent")
OUT = Path("data/benign_ds_agent_corpus.json")
REPOS = [
    "https://github.com/huggingface/notebooks",
    "https://github.com/tensorflow/docs",
    "https://github.com/fastai/fastbook",
    "https://github.com/ageron/handson-ml3",
    "https://github.com/GoogleCloudPlatform/vertex-ai-samples",
]


def clone():
    SRC.mkdir(parents=True, exist_ok=True)
    for url in REPOS:
        name = url.rstrip("/").split("/")[-1]
        if (SRC / name).exists():
            print(f"  have {name}"); continue
        print(f"  clone {name} ...")
        subprocess.run(["git", "clone", "--depth", "1", "--filter=blob:none", url, str(SRC / name)],
                       capture_output=True, timeout=600)


def extract():
    items = []
    for nb in SRC.glob("*/**/*.ipynb"):
        repo = nb.parts[nb.parts.index("benign_sources_dsagent") + 1]
        try:
            doc = json.loads(nb.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            continue
        for cell in doc.get("cells", []):
            if cell.get("cell_type") != "code":
                continue
            src = cell.get("source", [])
            if isinstance(src, str):
                src = src.splitlines()
            for line in src:
                line = line.strip()
                if line.startswith("!"):                    # shell command inside a notebook
                    cmd = line[1:].strip()
                    if cmd and "${" not in cmd and "{" not in cmd and 2 < len(cmd) < 300:
                        items.append({"command": cmd, "source_repo": repo,
                                      "source_file": str(nb.relative_to(SRC)), "kind": "notebook_shell",
                                      "domain": "data-science-agent"})
    seen, uniq = set(), []
    for it in items:
        if it["command"] not in seen:
            seen.add(it["command"]); uniq.append(it)
    return uniq


def load_ds_agent_benign():
    return json.loads(OUT.read_text())


def main():
    clone()
    items = extract()
    OUT.write_text(json.dumps(items, indent=2))
    from collections import Counter
    print(f"extracted {len(items)} DS-AGENT notebook-shell commands -> {OUT}")
    print("by repo:", dict(Counter(i["source_repo"] for i in items)))
    print("sample:")
    for it in items[:8]:
        print("  ", it["command"][:90])


if __name__ == "__main__":
    main()
