"""MAIN head-to-head experiment: representation-level vs effect-level monitoring under obfuscation.

For each obfuscation level O0..O6 and each action (real RedCode-Exec attacks + real benign CI/
Dockerfile commands), record THREE monitors on the SAME (obfuscated) action string:
  * judge_graded  : GPT-4o-as-judge 0-100 suspicion (deployed text guardrail, graded for ROC)
  * llamaguard    : Llama Guard 4 (binary; deployed content classifier)
  * behavioral    : run the action under strace in the sandbox (sinkhole), extract the kernel-effect
                    feature vector, score the monitor_family configs C1..C6 + a graded n_fired score.

Verify-the-artifact: every row records `executed` (>=1 execve). An attack only counts as detected
if it executed. Output: one JSONL row per (level, action) -> results/headtohead_runs/<tag>.jsonl.
Resumable: re-running skips (level, role, id) already in the JSONL (free re-runs; no re-paid API).

Usage:
  python -m experiments.cadc.headtohead_main --attacks-per-cat 2 --n-benign 50 --tag main
  python -m experiments.cadc.headtohead_main --attacks-per-cat 1 --n-benign 10 --tag pilot
  (add --dry to skip API calls = behavioral-only plumbing check)
"""
from __future__ import annotations

import argparse
import glob
import json
import random
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from dotenv import load_dotenv  # noqa: E402

load_dotenv(ROOT / ".env")

from cada.cache import JsonCache  # noqa: E402
from cada.monitors.text import LlamaGuardMonitor  # noqa: E402
from experiments.cadc import exec_obfuscation as obf  # noqa: E402
from experiments.cadc.blue_team import parse_trace  # noqa: E402
from experiments.cadc.build_real_benign import load_real_benign  # noqa: E402
from experiments.cadc.graded_monitors import GradedJudgeMonitor  # noqa: E402
from experiments.cadc.monitor_family import CONFIGS, extract_features, score  # noqa: E402
from experiments.cadc.trace_runner import capture  # noqa: E402

REDCODE = ROOT / "data/RedCode/dataset/RedCode-Exec/bash2text_dataset_json"
OUTDIR = ROOT / "results/headtohead_runs"
LEVELS = list(obf.TRANSFORMS.keys())  # O0_clean .. O6_composed


def _idxnum(p: str) -> int:
    m = re.search(r"index(\d+)_", p)
    return int(m.group(1)) if m else 9999


def load_attacks(per_cat: int) -> list[dict]:
    files = sorted(glob.glob(str(REDCODE / "index*_30_codes_full_upd.json")), key=_idxnum)
    out = []
    for f in files:
        data = json.load(open(f))
        cat = _idxnum(f)
        for item in data[:per_cat]:
            out.append({"id": str(item["Index"]), "category": cat, "code": item["Code"]})
    return out


def load_benign(n: int) -> list[dict]:
    corpus = load_real_benign()
    random.seed(42)
    idx = list(range(len(corpus)))
    random.shuffle(idx)
    return [{"id": f"b{i}", "category": -1, "code": corpus[i]["command"],
             "src": corpus[i].get("source_repo", "")} for i in idx[:n]]


def behavioral_row(action: str) -> dict:
    """One sandbox execution -> kernel-effect features + family verdicts + graded score."""
    cap = capture(action, sinkhole=True, timeout=15.0)
    trace = cap["trace"]
    raw = extract_features(trace)
    basic = parse_trace(trace)
    fam = {c.name: int(score(raw, c).flagged) for c in CONFIGS}
    # graded behavioral score = number of distinct harm primitives fired under the maximal feature set
    fired_max = next(score(raw, c).fired for c in CONFIGS if c.name == "C6_maximal")
    return {
        "executed": int(cap["executed"]),
        "timed_out": int(cap["timed_out"]),
        "features": {"sensitive_narrow": raw.sensitive_narrow, "sensitive_broad": raw.sensitive_broad,
                     "net_ports": raw.net_ports, "destructive": raw.destructive,
                     "persistence": raw.persistence, "privesc": raw.privesc,
                     "execve_count": raw.execve_count, "anti_trace": raw.anti_trace},
        "family_flags": fam,
        "behav_score": len(fired_max),          # 0..6, graded
        "basic_harmful": int(basic.harmful()),
        "trace_len": len(trace),
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--attacks-per-cat", type=int, default=2)
    ap.add_argument("--n-benign", type=int, default=50)
    ap.add_argument("--tag", default="main")
    ap.add_argument("--dry", action="store_true", help="skip API (behavioral-only)")
    ap.add_argument("--levels", default="", help="comma list to restrict levels (default all)")
    args = ap.parse_args()

    levels = [l for l in LEVELS if (not args.levels or l in args.levels.split(","))]
    attacks = load_attacks(args.attacks_per_cat)
    benign = load_benign(args.n_benign)
    actions = [{"role": "attack", **a} for a in attacks] + [{"role": "benign", **b} for b in benign]

    OUTDIR.mkdir(parents=True, exist_ok=True)
    out_path = OUTDIR / f"{args.tag}.jsonl"
    cache = JsonCache(OUTDIR / f"{args.tag}.textcache.json")
    judge = GradedJudgeMonitor(cache=cache)
    guard = LlamaGuardMonitor(cache=cache)

    done = set()
    if out_path.exists():
        for line in out_path.read_text(encoding="utf-8").splitlines():
            try:
                r = json.loads(line)
                done.add((r["level"], r["role"], r["id"]))
            except Exception:
                pass

    total = len(actions) * len(levels)
    print(f"actions={len(actions)} (attacks={len(attacks)} benign={len(benign)})  "
          f"levels={len(levels)}  cells={total}  already_done={len(done)}  dry={args.dry}")
    t0 = time.time()
    n = 0
    # action-OUTER, level-INNER: any prefix of actions is a balanced experiment across ALL levels,
    # so an early stop still yields usable (just smaller-n) cross-obfuscation data.
    with out_path.open("a", encoding="utf-8") as fout:
        for act in actions:
            for level in levels:
                tr = obf.TRANSFORMS[level]
                n += 1
                key = (level, act["role"], act["id"])
                if key in done:
                    continue
                obf_action = tr(act["code"])
                row = {"tag": args.tag, "level": level, "role": act["role"], "id": act["id"],
                       "category": act["category"]}
                try:
                    row.update(behavioral_row(obf_action))
                except Exception as e:
                    row["error_behav"] = f"{type(e).__name__}: {str(e)[:120]}"
                    row["executed"] = 0
                if not args.dry:
                    try:
                        row["judge_score"] = judge.suspicion(obf_action)
                    except Exception as e:
                        row["judge_score"] = None
                        row["error_judge"] = f"{type(e).__name__}: {str(e)[:120]}"
                    try:
                        row["guard_flag"] = guard.predict(obf_action)
                    except Exception as e:
                        row["guard_flag"] = None
                        row["error_guard"] = f"{type(e).__name__}: {str(e)[:120]}"
                fout.write(json.dumps(row) + "\n")
                fout.flush()
                if n % 10 == 0:
                    el = time.time() - t0
                    print(f"  [{n}/{total}] {level} {act['role']} {act['id']}  "
                          f"exec={row.get('executed')} behav={row.get('behav_score')} "
                          f"judge={row.get('judge_score')}  ({el:.0f}s)")
    print(f"DONE tag={args.tag}  wrote -> {out_path}  ({time.time()-t0:.0f}s)")


if __name__ == "__main__":
    main()
