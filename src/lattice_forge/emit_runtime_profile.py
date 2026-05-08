#!/usr/bin/env python3
"""Emit a RuntimeProfile export document from a RuntimeAsset.

The RuntimeProfile is a flat, self-contained document that Prophet Platform
artifact runners can consume to resolve and execute a runtime without
re-reading the full RuntimeAsset.  It captures the ProphetArtifact binding,
safety class, execution policy, and artifact digests needed for runner
launch and evidence recording.

Resolution format::

    runtime.profile: lattice-forge/<name>:<version>

Example::

    runtime.profile: lattice-forge/gaia-osm-ingest:0.1.0
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def emit_profile(runtime_asset: dict[str, Any]) -> dict[str, Any]:
    """Convert a RuntimeAsset document into a RuntimeProfile export.

    Parameters
    ----------
    runtime_asset:
        Parsed RuntimeAsset JSON object (already validated).

    Returns
    -------
    dict
        RuntimeProfile export document suitable for Prophet Platform ingestion.
    """
    metadata = runtime_asset.get("metadata", {})
    spec = runtime_asset.get("spec", {})
    labels = metadata.get("labels", {})
    name = metadata.get("name", "")
    version = metadata.get("version", "")

    artifact_digests = {
        item["name"]: item["digest"]
        for item in spec.get("artifacts", [])
        if isinstance(item, dict) and "name" in item and "digest" in item
    }

    profile: dict[str, Any] = {
        "apiVersion": "lattice.socioprophet.dev/v1",
        "kind": "RuntimeProfile",
        "profile": f"lattice-forge/{name}:{version}",
        "runtimeClass": spec.get("runtimeClass"),
        "languages": spec.get("languages", []),
        "policy": spec.get("policy", {}),
        "sbomDigest": spec.get("sbom", {}).get("digest"),
        "signatureDigest": spec.get("signature", {}).get("digest"),
        "provenanceBuilderId": spec.get("provenance", {}).get("builderId"),
        "promotionChannel": spec.get("promotion", {}).get("channel"),
        "artifactDigests": artifact_digests,
    }

    if labels.get("prophetArtifact"):
        profile["prophetArtifact"] = labels["prophetArtifact"]
    if labels.get("ownerRepo"):
        profile["ownerRepo"] = labels["ownerRepo"]
    if labels.get("safetyClass"):
        profile["safetyClass"] = labels["safetyClass"]

    return profile


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Emit RuntimeProfile export JSON from a RuntimeAsset file"
    )
    parser.add_argument("path", type=Path, help="Path to a RuntimeAsset JSON file")
    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        default=None,
        help="Write output to file instead of stdout",
    )
    args = parser.parse_args(argv)

    try:
        raw = args.path.read_text(encoding="utf-8")
        runtime_asset = json.loads(raw)
        if not isinstance(runtime_asset, dict):
            raise ValueError("RuntimeAsset file must contain a JSON object")
        profile = emit_profile(runtime_asset)
        output = json.dumps(profile, indent=2, sort_keys=True) + "\n"
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
            print(json.dumps({"written": str(args.output)}, indent=2, sort_keys=True))
        else:
            print(output, end="")
        return 0
    except Exception as exc:  # noqa: BLE001
        print(f"lattice-forge-emit-runtime-profile: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
