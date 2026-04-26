#!/usr/bin/env python3
"""Validate runtime evidence sidecar files.

This is a lightweight CI gate for the first evidence tranche. It does not claim
full SPDX, SLSA, or in-toto conformance; it verifies that the expected evidence
files exist and contain the required top-level fields before we wire dedicated
validators.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REQUIRED_FILES = {
    "kernel/kernel.json": ["argv", "display_name", "language", "metadata"],
    "evidence/sbom.spdx.json": ["spdxVersion", "SPDXID", "name", "creationInfo", "packages"],
    "evidence/provenance.intoto.json": ["_type", "subject", "predicateType", "predicate"],
    "evidence/scan.summary.json": ["runtimeAsset", "generatedAt", "status"],
}


def validate_runtime_dir(runtime_dir: Path) -> None:
    for rel_path, required_keys in REQUIRED_FILES.items():
        path = runtime_dir / rel_path
        if not path.exists():
            raise ValueError(f"missing required runtime evidence file: {path}")
        doc = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(doc, dict):
            raise ValueError(f"expected JSON object in {path}")
        missing = [key for key in required_keys if key not in doc]
        if missing:
            raise ValueError(f"{path} missing required keys: {', '.join(missing)}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate runtime evidence sidecars")
    parser.add_argument("runtime_dirs", nargs="+", type=Path)
    args = parser.parse_args(argv)

    failed = False
    for runtime_dir in args.runtime_dirs:
        try:
            validate_runtime_dir(runtime_dir)
            print(f"PASS {runtime_dir}")
        except Exception as exc:  # noqa: BLE001
            failed = True
            print(f"FAIL {runtime_dir}: {exc}", file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
