"""Single source of truth for capturing a RAW strace trace of one action in the cada-sandbox.

Returns the raw trace text so BOTH the basic monitor (blue_team.parse_trace) and the rich
monitor FAMILY (monitor_family.extract_features) can be derived from ONE execution. Uses the
sinkhole network by default so hostname-based egress issues an observable connect().
"""
from __future__ import annotations

import subprocess
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from experiments.cadc.blue_team import TRACED, _section  # noqa: E402

SINK_NET = "cadc_sink"
SINK_DNS = "172.19.0.2"


def capture(command: str, sinkhole: bool = True, timeout: float = 30.0,
            image: str = "cada-sandbox") -> dict:
    """Run `command` under strace in an isolated container; return raw trace + stdout + exec flag.

    Robustness: the workload is wrapped in a CONTAINER-SIDE `timeout`, so a runaway/looping attack
    self-terminates and the --rm container exits (no orphaned-container pile-up). The container is
    --name'd and force-removed if the outer client itself times out (a killed `docker run` client
    does NOT stop the daemon-side container, which was orphaning containers).
    """
    inner_to = max(5, int(timeout) - 3)
    inner = (
        "mkdir -p /work/out; cat > /work/cmd.sh; "
        f"timeout -k 2 {inner_to} strace -f -qq -e trace={TRACED} -o /work/tr.txt "
        "bash /work/cmd.sh > /work/stdout.txt 2>&1; "
        "echo '<<<TRACE>>>'; cat /work/tr.txt; "
        "echo '<<<STDOUT>>>'; cat /work/stdout.txt"
    )
    net = (["--network", SINK_NET, "--dns", SINK_DNS] if sinkhole else ["--network", "none"])
    name = f"cadc_cell_{uuid.uuid4().hex[:10]}"
    docker = ["docker", "run", "--rm", "-i", "--name", name, *net,
              "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
              "--cap-add", "SYS_PTRACE", "--pids-limit", "256", "--memory", "512m",
              image, "bash", "-c", inner]
    payload = command.replace("\r\n", "\n").replace("\r", "\n").encode("utf-8", "replace")
    timed_out = False
    try:
        proc = subprocess.run(docker, input=payload, capture_output=True, timeout=timeout)
        out = proc.stdout.decode("utf-8", "replace")
    except subprocess.TimeoutExpired as e:
        raw = e.stdout if isinstance(e.stdout, (bytes, bytearray)) else b""
        out = raw.decode("utf-8", "replace")
        timed_out = True
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)  # kill the orphan
    trace = _section(out, "<<<TRACE>>>", "<<<STDOUT>>>")
    stdout = _section(out, "<<<STDOUT>>>", None)
    executed = bool(trace and "execve(" in trace)
    return {"trace": trace, "stdout": stdout, "executed": executed, "timed_out": timed_out}


__all__ = ["capture", "SINK_NET", "SINK_DNS"]
