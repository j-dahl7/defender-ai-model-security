#!/usr/bin/env python3
"""Convert modelscan JSON output to SARIF 2.1.0.

Usage:
    python modelscan_to_sarif.py <modelscan.json> <output.sarif>
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

SEVERITY_TO_SARIF = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
}


def issue_to_result(issue: dict) -> dict:
    severity = issue.get("severity", "MEDIUM").upper()
    level = SEVERITY_TO_SARIF.get(severity, "warning")
    scanner = issue.get("scanner", "modelscan")
    message = (
        f"{issue.get('description', 'Unsafe model operator detected')} "
        f"(operator={issue.get('operator')}, module={issue.get('module')})"
    )
    return {
        "ruleId": scanner,
        "level": level,
        "message": {"text": message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": issue.get("source", "unknown")},
                }
            }
        ],
        "properties": {"severity": severity},
    }


def error_to_result(err: dict) -> dict:
    return {
        "ruleId": err.get("category", "modelscan.parse-error"),
        "level": "note",
        "message": {"text": err.get("description", "Parsing error")},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": err.get("source", "unknown")},
                }
            }
        ],
    }


def convert(report: dict) -> dict:
    issues = report.get("issues", [])
    errors = report.get("errors", [])
    rules = {}
    for issue in issues:
        scanner = issue.get("scanner", "modelscan")
        rules.setdefault(
            scanner,
            {
                "id": scanner,
                "name": scanner.rsplit(".", 1)[-1],
                "shortDescription": {"text": "Unsafe model operator"},
                "fullDescription": {
                    "text": "Detects unsafe operators embedded in ML model artifacts."
                },
                "help": {"text": "See https://github.com/protectai/modelscan"},
                "defaultConfiguration": {"level": "error"},
            },
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "modelscan",
                        "informationUri": "https://github.com/protectai/modelscan",
                        "version": report.get("summary", {}).get(
                            "modelscan_version", "unknown"
                        ),
                        "rules": list(rules.values()),
                    }
                },
                "results": [issue_to_result(i) for i in issues]
                + [error_to_result(e) for e in errors],
            }
        ],
    }


def main() -> int:
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <modelscan.json> <output.sarif>", file=sys.stderr)
        return 2
    src = Path(sys.argv[1])
    dst = Path(sys.argv[2])
    dst.parent.mkdir(parents=True, exist_ok=True)
    report = json.loads(src.read_text())
    dst.write_text(json.dumps(convert(report), indent=2))
    print(f"Wrote {dst}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
