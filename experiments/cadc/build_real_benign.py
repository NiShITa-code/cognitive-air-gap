"""Mechanically extract a REAL benign command corpus from cloned public repos.

Anti-fake: every command is a verbatim shell line from a real public CI workflow (.github/
workflows/*.yml `run:` steps), Dockerfile `RUN`, or Makefile recipe — with provenance (repo +
file). No templates, no hand-authoring. These are commands real maintainers run in production CI,
so they are ground-truth benign by virtue of being merged into actively-used projects.

Output: data/benign_real_corpus.json  (list of {command, source_repo, source_file, kind}).
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

SRC = Path("data/benign_sources")
OUT = Path("data/benign_real_corpus.json")


def _walk_runs(obj):
    """Yield every string value under a 'run' key, anywhere in a parsed YAML tree."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == "run" and isinstance(v, str):
                yield v
            else:
                yield from _walk_runs(v)
    elif isinstance(obj, list):
        for it in obj:
            yield from _walk_runs(it)


# PowerShell / Windows-CI markers — these run: steps are not bash and must be excluded.
_PWSH = re.compile(r"\$LASTEXITCODE|Write-Host|Get-|Set-|\$env:|-eq |__powershell|\bif\s*\(")


def _clean_block(block: str) -> str | None:
    """Keep a run: step as ONE coherent bash action, or None if it isn't clean bash.

    A run: step is exactly what a CI agent executes as one step — the right unit for FPR.
    We do NOT fragment it into lines (that produced noise like '--title ...' continuations).
    We exclude: GitHub Actions templating (not runnable verbatim) and PowerShell steps.
    """
    block = block.strip()
    if not block:
        return None
    if "${{" in block:                    # GH Actions template expr — not runnable verbatim
        return None
    if _PWSH.search(block):               # PowerShell / Windows CI step — not bash
        return None
    # strip pure-comment lines but keep the multi-line command intact
    lines = [ln for ln in block.splitlines() if ln.strip() and not ln.strip().startswith("#")]
    return "\n".join(lines) if lines else None


def extract() -> list[dict]:
    items: list[dict] = []
    # 1) GitHub Actions run: steps
    for wf in SRC.glob("*/.github/workflows/*.y*ml"):
        repo = wf.parts[wf.parts.index("benign_sources") + 1]
        try:
            doc = yaml.safe_load(wf.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            continue
        for block in _walk_runs(doc):
            cmd = _clean_block(block)
            if cmd:
                items.append({"command": cmd, "source_repo": repo,
                              "source_file": str(wf.relative_to(SRC)), "kind": "ci_workflow"})
    # 2) Dockerfile RUN lines
    for df in SRC.glob("**/Dockerfile*"):
        repo = df.parts[df.parts.index("benign_sources") + 1]
        txt = df.read_text(encoding="utf-8", errors="replace")
        for m in re.finditer(r"^RUN\s+(.+)$", txt, re.MULTILINE):
            cmd = m.group(1).strip().rstrip("\\").strip()
            if cmd and "${{" not in cmd:
                items.append({"command": cmd, "source_repo": repo,
                              "source_file": str(df.relative_to(SRC)), "kind": "dockerfile"})
    # dedup by command text, keep first provenance
    seen, uniq = set(), []
    for it in items:
        if it["command"] not in seen:
            seen.add(it["command"]); uniq.append(it)
    return uniq


def load_real_benign() -> list[dict]:
    """Load the mechanically-extracted real benign corpus (command + provenance)."""
    return json.loads(OUT.read_text())


def main() -> None:
    items = extract()
    OUT.write_text(json.dumps(items, indent=2))
    from collections import Counter
    by_repo = Counter(i["source_repo"] for i in items)
    by_kind = Counter(i["kind"] for i in items)
    print(f"extracted {len(items)} REAL benign commands -> {OUT}")
    print("by repo:", dict(by_repo))
    print("by kind:", dict(by_kind))
    print("\n--- 8 random examples with provenance ---")
    import random
    random.seed(0)
    for it in random.sample(items, min(8, len(items))):
        line = f"[{it['source_repo']}:{it['kind']}] {it['command'][:90]}"
        print(line.encode("ascii", "replace").decode("ascii"))  # console-safe


if __name__ == "__main__":
    main()
