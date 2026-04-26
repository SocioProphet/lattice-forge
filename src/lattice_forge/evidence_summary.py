#!/usr/bin/env python3
"""Generate a compact runtime evidence summary.

This tool is intentionally side-effect-free. It reads a RuntimeAsset descriptor
and expected evidence sidecars, then emits a single JSON summary suitable for
Prophet Platform ingestion or premerge inspection.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


EVIDENCE_PATHS = {
    "kernel": "kernel/kernel.json",
    "sbom": "evidence/sbom.spdx.json",
    "provenance": "evidence/provenance.intoto.json",
    "scan": "evidence/scan.summary.json",
}


def load_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"expected JSON object in {path}")
    return data


def summarize(runtime_dir: Path) -> dict[str, Any]:
    runtime_asset_path = runtime_dir / "runtime-asset.json"
    runtime_asset = load_json(runtime_asset_path)
    metadata = runtime_asset.get("metadata", {})
    spec = runtime_asset.get("spec", {})

    evidence = {}
    for name, rel_path in EVIDENCE_PATHS.items():
        path = runtime_dir / rel_path
        doc = load_json(path)
        evidence[name] = {
            "path": rel_path,
            "present": True,
            "topLevelKeys": sorted(doc.keys()),
        }

    return {
        "apiVersion": "lattice.socioprophet.dev/v1",
        "kind": "RuntimeEvidenceSummary",
        "runtime": {
            "name": metadata.get("name"),
            "version": metadata.get("version"),
            "runtimeClass": spec.get("runtimeClass"),
            "languages": spec.get("languages", []),
            "promotion": spec.get("promotion", {}),
        },
        "policy": spec.get("policy", {}),
        "compatibility": spec.get("compatibility", {}),
        "evidence": evidence,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate RuntimeEvidenceSummary JSON")
    parser.add_argument("runtime_dir", type=Path)
    args = parser.parse_args(argv)

    try:
        print(json.dumps(summarize(args.runtime_dir), indent=2, sort_keys=True))
        return 0
    except Exception as exc:  # noqa: BLE001
        print(f"lattice-forge-evidence-summary: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
