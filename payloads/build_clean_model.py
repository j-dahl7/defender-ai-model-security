"""Build a clean baseline model.

Trains a RandomForest on sklearn's iris dataset and persists it via joblib
(pickle under the hood). This is the negative control — Defender should NOT
alert on this file.
"""
from __future__ import annotations

import joblib
from pathlib import Path
from sklearn.datasets import load_iris
from sklearn.ensemble import RandomForestClassifier


def main(out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    X, y = load_iris(return_X_y=True)
    model = RandomForestClassifier(n_estimators=10, random_state=42)
    model.fit(X, y)
    out_path = out_dir / "clean_iris_rf.pkl"
    joblib.dump(model, out_path)
    print(f"Wrote {out_path} ({out_path.stat().st_size} bytes)")


if __name__ == "__main__":
    main(Path(__file__).resolve().parent / "artifacts")
