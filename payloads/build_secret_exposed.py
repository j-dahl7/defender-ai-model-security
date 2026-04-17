"""Build a model pickle with exposed secrets baked into the serialized state.

Common accidental pattern: developers pickle a training config object that
contains API keys, cloud credentials, or connection strings. When the model
is uploaded to a shared registry, every downstream consumer can extract those
secrets with pickletools.

Defender for AI Services secret scanner looks for high-entropy strings that
match known credential formats (AWS access keys, Azure SAS tokens, GitHub
PATs, private keys, etc.) inside model artifacts.
"""
from __future__ import annotations

import pickle
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class TrainingConfig:
    """Simulates an accidentally pickled config with embedded secrets.

    None of these are real credentials — they match the format detectors
    look for but point nowhere. Replace with synthetic values only.
    """

    model_name: str = "sentiment-classifier-v3"
    learning_rate: float = 1e-4
    epochs: int = 10
    # Format-valid but fake credentials — detectors pattern-match on shape.
    aws_access_key_id: str = "AKIAIOSFODNN7EXAMPLE"
    aws_secret_access_key: str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    github_pat: str = "ghp_1234567890abcdef1234567890abcdef12345678"
    azure_sas: str = (
        "?sv=2022-11-02&ss=b&srt=sco&sp=rwdlacupitfx"
        "&se=2030-01-01T00:00:00Z&st=2024-01-01T00:00:00Z"
        "&spr=https&sig=EXAMPLEfakeSignatureDoNotUse%3D"
    )
    notes: list[str] = field(default_factory=lambda: [
        "Loaded from secrets/prod.env at train time — left in by accident.",
    ])


@dataclass
class ModelBundle:
    """Wraps a trivial model with the compromising config."""

    weights: list[float]
    config: TrainingConfig


def main(out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    bundle = ModelBundle(
        weights=[0.1, -0.3, 0.8, 0.42, -0.15],
        config=TrainingConfig(),
    )
    out_path = out_dir / "secret_exposed_model.pkl"
    with out_path.open("wb") as f:
        pickle.dump(bundle, f)
    print(f"Wrote {out_path} ({out_path.stat().st_size} bytes)")
    print("Secrets embedded (all fake format-valid values, not real credentials).")


if __name__ == "__main__":
    main(Path(__file__).resolve().parent / "artifacts")
