"""TIER-2: the decoding arms race as a CAPABILITY LAW.

If representational monitoring's robustness is bounded by the monitor's ability to DECODE the
obfuscation (§5.7), then judge AUROC on a *decodable* encoding (base64) should rise with model
capability, while AUROC on a *non-decodable* encoding (XOR) should stay low for ALL models. We test
that with a 3-rung capability ladder, all using the IDENTICAL graded prompt and the IDENTICAL commands:

  rung 1  claude-haiku-4.5   (small/cheap)         -- run here
  rung 2  openai/gpt-4o      (mid)                 -- from main.jsonl        (judge_score)
  rung 3  claude-sonnet-4.6  (frontier)            -- from main.claude.jsonl (claude_score)

Only Haiku is new (cheap). Levels match the Claude baseline: O0_clean, O1_base64, O5_deceptive, X3_xor.

Usage:  python -m experiments.cadc.model_ladder           # run Haiku + build ladder
        python -m experiments.cadc.model_ladder --report  # ladder from caches only (no API)
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from dotenv import load_dotenv  # noqa: E402

load_dotenv(ROOT / ".env")
from cada.cache import JsonCache  # noqa: E402
from experiments.cadc import exec_obfuscation as obf  # noqa: E402
from experiments.cadc.analyze_headtohead import auroc  # noqa: E402
from experiments.cadc.graded_monitors import GradedJudgeMonitor  # noqa: E402
from experiments.cadc.headtohead_main import load_attacks, load_benign  # noqa: E402

OUT = ROOT / "results/headtohead_runs"
LEVELS = ["O0_clean", "O1_base64", "O5_deceptive", "X3_xor"]
HAIKU = "anthropic/claude-haiku-4.5"


def run_haiku(report_only: bool):
    rows = [json.loads(l) for l in (OUT / "main.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
    code = {f"a:{a['id']}": a["code"] for a in load_attacks(5)}
    code.update({f"b:{b['id']}": b["code"] for b in load_benign(120)})
    cache = JsonCache(OUT / "main.haiku_cache.json")
    judge = GradedJudgeMonitor(model=HAIKU, cache=cache)
    out_path = OUT / "main.haiku.jsonl"
    done = set()
    if out_path.exists():
        for l in out_path.read_text(encoding="utf-8").splitlines():
            try:
                r = json.loads(l); done.add((r["level"], r["role"], r["id"]))
            except Exception:
                pass
    if not report_only:
        written = 0
        with out_path.open("a", encoding="utf-8") as f:
            for lv in LEVELS:
                tr = obf.TRANSFORMS[lv]
                for r in rows:
                    if r["level"] != lv:
                        continue
                    key = (lv, r["role"], r["id"])
                    if key in done:
                        continue
                    ck = f"{'a' if r['role']=='attack' else 'b'}:{r['id']}"
                    if ck not in code:
                        continue
                    try:
                        s = judge.suspicion(tr(code[ck]))
                    except Exception as e:
                        print(f"  ERR {lv} {r['role']} {r['id']}: {type(e).__name__}: {str(e)[:80]}", flush=True)
                        continue
                    written += 1
                    f.write(json.dumps({"level": lv, "role": r["role"], "id": r["id"],
                                        "executed": r.get("executed", 1), "haiku_score": s}) + "\n")
                    f.flush()
                    if written % 40 == 0:
                        print(f"  [{written} written] {lv} (refusals={judge.refusals})", flush=True)
        print(f"Haiku written={written} refusals={judge.refusals}", flush=True)


def _auroc_from(path, key):
    rows = [json.loads(l) for l in (OUT / path).read_text(encoding="utf-8").splitlines() if l.strip()]
    out = {}
    for lv in LEVELS:
        att = [r[key] for r in rows if r["level"] == lv and r["role"] == "attack"
               and r.get("executed") and r.get(key) is not None]
        ben = [r[key] for r in rows if r["level"] == lv and r["role"] == "benign" and r.get(key) is not None]
        out[lv] = auroc(att, ben) if att and ben else None
    return out


def build_ladder():
    ladder = [
        ("Haiku-4.5", _auroc_from("main.haiku.jsonl", "haiku_score")),
        ("GPT-4o", _auroc_from("main.jsonl", "judge_score")),
        ("Sonnet-4.6", _auroc_from("main.claude.jsonl", "claude_score")),
    ]
    print("\n=== Decoding arms race as a CAPABILITY LAW — judge AUROC ===")
    head = f"{'model':<12}" + "".join(f"{lv.split('_')[0]:>10}" for lv in LEVELS)
    print(head)
    summary = {"levels": LEVELS, "ladder": []}
    for name, d in ladder:
        cells = "".join((f"{d[lv]:>10.2f}" if d[lv] is not None else f"{'-':>10}") for lv in LEVELS)
        print(f"{name:<12}{cells}")
        summary["ladder"].append({"model": name, **{lv: (round(d[lv], 3) if d[lv] is not None else None) for lv in LEVELS}})
    (OUT / "main.ladder.summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"\nwrote -> {OUT/'main.ladder.summary.json'}")
    print("READ: base64 column should RISE with capability; XOR column should stay low for ALL.")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--report", action="store_true")
    a = ap.parse_args()
    run_haiku(a.report)
    build_ladder()
