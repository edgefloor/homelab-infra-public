#!/usr/bin/env python3
"""Validate saved synthetic/sanitized investigations and preview alerts without sending them."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ansible/roles/homelab_agent_service/files"))
from homelab_investigation import validate_investigation
from homelab_cve_alert import render_alert


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixtures", type=Path, nargs="*")
    parser.add_argument(
        "--output", type=Path, help="Write the complete rendered examples for review"
    )
    args = parser.parse_args()
    files = args.fixtures or sorted((ROOT / "scripts/fixtures/cve").glob("*.json"))
    sections = []
    for file in files:
        data = json.loads(file.read_text())
        record = data["record"]
        receipts = data["receipts"]
        validate_investigation(record["investigation"], record["scope"], receipts)
        pages = render_alert(record)
        assessments = sum(len(g["paths"]) for g in record["investigation"]["groups"])
        failures = sum(r["status"] != "success" for r in receipts)
        print(
            json.dumps(
                {
                    "fixture": file.name,
                    "assessments": assessments,
                    "observations": len(receipts),
                    "failed_observations": failures,
                    "messages": len(pages),
                    "message_words": [len(p.split()) for p in pages],
                },
                separators=(",", ":"),
            )
        )
        sections.append(f"# {file.stem}\n\n" + "\n\n---\n\n".join(pages))
    if args.output:
        args.output.write_text("\n\n".join(sections) + "\n")


if __name__ == "__main__":
    main()
