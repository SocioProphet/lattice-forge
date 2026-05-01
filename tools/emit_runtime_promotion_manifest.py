#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
BUILD_DIR = ROOT / "build" / "runtime-assets"
PROFILES = ["prophet-python-ml", "prophet-ray-ml", "prophet-beam-dataops"]
OUTPUT = BUILD_DIR / "runtime-promotion-manifest.json"


def digest_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def digest_file(path: Path) -> str:
    return digest_bytes(path.read_bytes())


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def evidence_entry(path: Path, role: str) -> dict[str, str]:
    return {
        "role": role,
        "uri": path.relative_to(ROOT).as_posix(),
        "digest": digest_file(path),
    }


def profile_manifest(profile: str) -> dict[str, Any]:
    runtime_path = BUILD_DIR / f"{profile}.runtime-asset.json"
    runtime = load_json(runtime_path)
    spec = runtime["spec"]
    evidence = [
        evidence_entry(runtime_path, "runtime-asset"),
        evidence_entry(BUILD_DIR / f"{profile}.sbom.spdx.json", "sbom"),
        evidence_entry(BUILD_DIR / f"{profile}.scan.json", "scan-report"),
        evidence_entry(BUILD_DIR / f"{profile}.attestation.json", "attestation"),
        evidence_entry(BUILD_DIR / f"{profile}.sigstore.bundle.json", "signature"),
    ]
    scan = load_json(BUILD_DIR / f"{profile}.scan.json")
    signature = load_json(BUILD_DIR / f"{profile}.sigstore.bundle.json")
    attestation = load_json(BUILD_DIR / f"{profile}.attestation.json")
    promotion_channel = spec["promotion"]["channel"]
    generated_gates = {
        "requiredEvidencePresent": all((ROOT / item["uri"]).exists() for item in evidence),
        "scanPass": scan.get("vulnerability") == "pass" and scan.get("license") == "pass" and scan.get("policy") == "pass",
        "signaturePresent": signature.get("type") == "sigstore" and signature.get("bundleDigest", "").startswith("sha256:"),
        "provenancePresent": attestation.get("predicateType") == "https://slsa.dev/provenance/v1",
        "runtimeAssetReferencesSidecars": all(
            item["uri"] in {artifact.get("uri") for artifact in spec.get("artifacts", [])}
            for item in evidence
            if item["role"] != "runtime-asset"
        ),
    }
    stable_blockers = []
    if promotion_channel != "stable":
        stable_blockers.append("promotion.channel is not stable")
    stable_blockers.append("external scanner and external signing authority evidence not yet attached")
    return {
        "runtimeAssetRef": f"runtime-asset:{profile}:0.1.0",
        "runtimeName": profile,
        "runtimeClass": spec["runtimeClass"],
        "promotionChannel": promotion_channel,
        "evidence": evidence,
        "generatedEvidenceGates": generated_gates,
        "devPromotionAllowed": all(generated_gates.values()) and promotion_channel == "dev",
        "stablePromotionAllowed": False,
        "stablePromotionBlockers": stable_blockers,
        "policyRef": f"policy://runtime/{profile}-demo",
    }


def main() -> int:
    profiles = [profile_manifest(profile) for profile in PROFILES]
    payload = {
        "apiVersion": "lattice.socioprophet.dev/v1",
        "kind": "RuntimePromotionManifest",
        "metadata": {
            "name": "lattice-runtime-promotion-manifest",
            "version": "0.1.0",
            "generatedBy": "tools/emit_runtime_promotion_manifest.py",
        },
        "profiles": profiles,
        "policy": {
            "devPromotionRequiresGeneratedEvidence": True,
            "stablePromotionRequiresExternalScanner": True,
            "stablePromotionRequiresExternalSigningAuthority": True,
            "stablePromotionRequiresHumanApproval": True,
        },
    }
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"written": str(OUTPUT)}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
