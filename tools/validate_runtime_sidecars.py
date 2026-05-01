#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
BUILD_DIR = ROOT / "build" / "runtime-assets"
PROFILES = ["prophet-python-ml", "prophet-ray-ml", "prophet-beam-dataops"]
SHA256_RE = re.compile(r"^sha256:[a-f0-9]{64}$")


def fail(message: str) -> int:
    print(f"ERR: {message}", file=sys.stderr)
    return 1


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def load_json(path: Path) -> dict[str, Any]:
    require(path.exists(), f"missing {path}")
    value = json.loads(path.read_text(encoding="utf-8"))
    require(isinstance(value, dict), f"{path} must contain a JSON object")
    return value


def digest_ok(value: str) -> bool:
    return SHA256_RE.match(value) is not None


def validate_profile(profile: str) -> None:
    runtime = load_json(BUILD_DIR / f"{profile}.runtime-asset.json")
    sbom = load_json(BUILD_DIR / f"{profile}.sbom.spdx.json")
    scan = load_json(BUILD_DIR / f"{profile}.scan.json")
    attestation = load_json(BUILD_DIR / f"{profile}.attestation.json")
    signature = load_json(BUILD_DIR / f"{profile}.sigstore.bundle.json")

    require(runtime["metadata"]["name"] == profile, f"{profile}: RuntimeAsset metadata.name mismatch")
    artifact_names = {artifact["name"] for artifact in runtime["spec"]["artifacts"]}
    for suffix in ["sbom.spdx.json", "scan.json", "attestation.json", "sigstore.bundle.json"]:
        name = f"build/runtime-assets/{profile}.{suffix}"
        require(name in artifact_names, f"{profile}: RuntimeAsset missing artifact {name}")

    require(sbom.get("spdxVersion") == "SPDX-2.3", f"{profile}: SBOM SPDX version mismatch")
    require(sbom.get("name") == profile, f"{profile}: SBOM name mismatch")
    require(isinstance(sbom.get("packages"), list) and len(sbom["packages"]) >= 3, f"{profile}: SBOM must list runtime source artifacts")

    require(scan.get("runtime") == profile, f"{profile}: scan runtime mismatch")
    for key in ["vulnerability", "license", "policy"]:
        require(scan.get(key) == "pass", f"{profile}: scan.{key} must be pass")
    require(isinstance(scan.get("scannedArtifacts"), list) and scan["scannedArtifacts"], f"{profile}: scannedArtifacts missing")

    require(attestation.get("runtime") == profile, f"{profile}: attestation runtime mismatch")
    require(attestation.get("builderId") == "lattice-forge-demo-builder", f"{profile}: builderId mismatch")
    require(attestation.get("predicateType") == "https://slsa.dev/provenance/v1", f"{profile}: predicateType mismatch")
    require(isinstance(attestation.get("subject"), list) and attestation["subject"], f"{profile}: attestation subject missing")

    require(signature.get("runtime") == profile, f"{profile}: signature runtime mismatch")
    require(signature.get("type") == "sigstore", f"{profile}: signature type mismatch")
    require(digest_ok(signature.get("subjectDigest", "")), f"{profile}: signature subjectDigest invalid")
    require(digest_ok(signature.get("bundleDigest", "")), f"{profile}: signature bundleDigest invalid")
    require(runtime["spec"]["signature"]["bundleRef"] == f"build/runtime-assets/{profile}.sigstore.bundle.json", f"{profile}: signature bundleRef mismatch")
    require(runtime["spec"]["scan"] == {"vulnerability": "pass", "license": "pass", "policy": "pass"}, f"{profile}: RuntimeAsset scan summary mismatch")


def main() -> int:
    try:
        for profile in PROFILES:
            validate_profile(profile)
    except Exception as exc:  # noqa: BLE001
        return fail(str(exc))
    print(json.dumps({"ok": True, "profiles": PROFILES}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
