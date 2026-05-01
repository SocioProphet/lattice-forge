#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
BUILD_DIR = ROOT / "build" / "runtime-assets"
MANIFEST = BUILD_DIR / "runtime-promotion-manifest.json"
PROFILES = {
    "runtime-asset:prophet-python-ml:0.1.0": "notebook",
    "runtime-asset:prophet-ray-ml:0.1.0": "ray",
    "runtime-asset:prophet-beam-dataops:0.1.0": "beam",
}
REQUIRED_EVIDENCE_ROLES = {"runtime-asset", "sbom", "scan-report", "attestation", "signature"}
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")


def fail(message: str) -> int:
    print(f"ERR: {message}", file=sys.stderr)
    return 1


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def load_json(path: Path) -> dict[str, Any]:
    require(path.exists(), f"missing {path}")
    value = json.loads(path.read_text(encoding="utf-8"))
    require(isinstance(value, dict), f"{path} must contain JSON object")
    return value


def digest_ok(value: str) -> bool:
    return DIGEST.match(value) is not None


def validate_profile(profile: dict[str, Any]) -> str:
    ref = profile.get("runtimeAssetRef")
    require(ref in PROFILES, f"unexpected runtimeAssetRef {ref}")
    require(profile.get("runtimeClass") == PROFILES[ref], f"{ref}: runtimeClass mismatch")
    require(profile.get("promotionChannel") == "dev", f"{ref}: promotionChannel must remain dev")
    evidence = profile.get("evidence")
    require(isinstance(evidence, list), f"{ref}: evidence must be list")
    roles = {item.get("role") for item in evidence if isinstance(item, dict)}
    require(roles == REQUIRED_EVIDENCE_ROLES, f"{ref}: evidence roles mismatch {roles}")
    for item in evidence:
        require(isinstance(item, dict), f"{ref}: evidence entries must be objects")
        uri = item.get("uri")
        digest = item.get("digest")
        require(isinstance(uri, str) and uri, f"{ref}: evidence uri missing")
        require((ROOT / uri).exists(), f"{ref}: evidence file missing {uri}")
        require(isinstance(digest, str) and digest_ok(digest), f"{ref}: evidence digest invalid")
    gates = profile.get("generatedEvidenceGates")
    require(isinstance(gates, dict), f"{ref}: generatedEvidenceGates must be object")
    for key in ["requiredEvidencePresent", "scanPass", "signaturePresent", "provenancePresent", "runtimeAssetReferencesSidecars"]:
        require(gates.get(key) is True, f"{ref}: gate {key} must be true")
    require(profile.get("devPromotionAllowed") is True, f"{ref}: devPromotionAllowed must be true")
    require(profile.get("stablePromotionAllowed") is False, f"{ref}: stablePromotionAllowed must be false")
    blockers = profile.get("stablePromotionBlockers")
    require(isinstance(blockers, list) and blockers, f"{ref}: stablePromotionBlockers must be non-empty")
    require(any("external scanner" in item for item in blockers), f"{ref}: stable promotion must require external scanner evidence")
    require(any("external signing" in item for item in blockers), f"{ref}: stable promotion must require external signing evidence")
    return ref


def main() -> int:
    try:
        manifest = load_json(MANIFEST)
        require(manifest.get("apiVersion") == "lattice.socioprophet.dev/v1", "apiVersion mismatch")
        require(manifest.get("kind") == "RuntimePromotionManifest", "kind mismatch")
        profiles = manifest.get("profiles")
        require(isinstance(profiles, list), "profiles must be list")
        refs = {validate_profile(profile) for profile in profiles if isinstance(profile, dict)}
        require(refs == set(PROFILES), f"profile refs mismatch: {sorted(refs)}")
        policy = manifest.get("policy")
        require(isinstance(policy, dict), "policy must be object")
        require(policy.get("devPromotionRequiresGeneratedEvidence") is True, "dev policy gate missing")
        require(policy.get("stablePromotionRequiresExternalScanner") is True, "stable scanner gate missing")
        require(policy.get("stablePromotionRequiresExternalSigningAuthority") is True, "stable signing gate missing")
        require(policy.get("stablePromotionRequiresHumanApproval") is True, "stable approval gate missing")
    except Exception as exc:  # noqa: BLE001
        return fail(str(exc))
    print(json.dumps({"ok": True, "validated": str(MANIFEST)}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
