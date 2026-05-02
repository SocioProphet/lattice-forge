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
REQUIRED_EVIDENCE_ROLES = {
    "runtime-asset",
    "sbom",
    "scan-report",
    "attestation",
    "signature",
    "external-scanner-evidence",
    "external-signing-authority-evidence",
    "human-approval",
}
REQUIRED_GENERATED_GATES = {
    "requiredEvidencePresent",
    "scanPass",
    "signaturePresent",
    "provenancePresent",
    "runtimeAssetReferencesSidecars",
}
REQUIRED_STABLE_GATES = {
    "externalScannerEvidencePresent",
    "externalScannerPass",
    "externalSigningAuthorityEvidencePresent",
    "externalSigningAuthorityVerified",
    "humanApprovalEvidencePresent",
    "humanApprovalApproved",
}
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


def validate_external_evidence(ref: str, role_to_path: dict[str, Path]) -> None:
    scanner = load_json(role_to_path["external-scanner-evidence"])
    require(scanner.get("kind") == "ExternalScannerEvidence", f"{ref}: scanner kind mismatch")
    require(scanner.get("runtimeAssetRef") == ref, f"{ref}: scanner runtime ref mismatch")
    require(scanner.get("result") == "pass", f"{ref}: scanner result must pass")
    checks = scanner.get("checks")
    require(isinstance(checks, dict), f"{ref}: scanner checks must be object")
    for key in ["vulnerability", "license", "policy"]:
        require(checks.get(key) == "pass", f"{ref}: scanner {key} must pass")
    require(checks.get("sbomDigestVerified") is True, f"{ref}: scanner must verify SBOM digest")
    require(checks.get("runtimeAssetDigestVerified") is True, f"{ref}: scanner must verify runtime digest")

    signing = load_json(role_to_path["external-signing-authority-evidence"])
    require(signing.get("kind") == "ExternalSigningAuthorityEvidence", f"{ref}: signing kind mismatch")
    require(signing.get("runtimeAssetRef") == ref, f"{ref}: signing runtime ref mismatch")
    require(signing.get("result") == "verified", f"{ref}: signing result must be verified")
    require(digest_ok(signing.get("signedSubjectDigest", "")), f"{ref}: signedSubjectDigest invalid")
    require(digest_ok(signing.get("scannerEvidenceDigest", "")), f"{ref}: scannerEvidenceDigest invalid")
    require(digest_ok(signing.get("signatureBundleDigest", "")), f"{ref}: signatureBundleDigest invalid")

    approval = load_json(role_to_path["human-approval"])
    require(approval.get("kind") == "HumanApprovalEvidence", f"{ref}: approval kind mismatch")
    require(approval.get("runtimeAssetRef") == ref, f"{ref}: approval runtime ref mismatch")
    require(approval.get("approvalState") == "approved", f"{ref}: approvalState must be approved")
    require(approval.get("approverRole") == "runtime-release-owner", f"{ref}: approverRole mismatch")
    require(digest_ok(approval.get("externalScannerEvidenceDigest", "")), f"{ref}: approval scanner digest invalid")
    require(digest_ok(approval.get("externalSigningAuthorityEvidenceDigest", "")), f"{ref}: approval signing digest invalid")


def validate_profile(profile: dict[str, Any]) -> str:
    ref = profile.get("runtimeAssetRef")
    require(ref in PROFILES, f"unexpected runtimeAssetRef {ref}")
    require(profile.get("runtimeClass") == PROFILES[ref], f"{ref}: runtimeClass mismatch")
    require(profile.get("promotionChannel") == "dev", f"{ref}: promotionChannel remains dev while stable evidence is attached")
    evidence = profile.get("evidence")
    require(isinstance(evidence, list), f"{ref}: evidence must be list")
    roles = {item.get("role") for item in evidence if isinstance(item, dict)}
    require(roles == REQUIRED_EVIDENCE_ROLES, f"{ref}: evidence roles mismatch {roles}")
    role_to_path: dict[str, Path] = {}
    for item in evidence:
        require(isinstance(item, dict), f"{ref}: evidence entries must be objects")
        role = item.get("role")
        uri = item.get("uri")
        digest = item.get("digest")
        require(isinstance(role, str) and role, f"{ref}: evidence role missing")
        require(isinstance(uri, str) and uri, f"{ref}: evidence uri missing")
        require((ROOT / uri).exists(), f"{ref}: evidence file missing {uri}")
        require(isinstance(digest, str) and digest_ok(digest), f"{ref}: evidence digest invalid")
        role_to_path[role] = ROOT / uri
    validate_external_evidence(ref, role_to_path)

    generated_gates = profile.get("generatedEvidenceGates")
    require(isinstance(generated_gates, dict), f"{ref}: generatedEvidenceGates must be object")
    for key in REQUIRED_GENERATED_GATES:
        require(generated_gates.get(key) is True, f"{ref}: generated gate {key} must be true")
    stable_gates = profile.get("stableEvidenceGates")
    require(isinstance(stable_gates, dict), f"{ref}: stableEvidenceGates must be object")
    for key in REQUIRED_STABLE_GATES:
        require(stable_gates.get(key) is True, f"{ref}: stable gate {key} must be true")
    require(profile.get("devPromotionAllowed") is True, f"{ref}: devPromotionAllowed must be true")
    require(profile.get("stablePromotionAllowed") is True, f"{ref}: stablePromotionAllowed must be true when stable evidence exists")
    blockers = profile.get("stablePromotionBlockers")
    require(blockers == [], f"{ref}: stablePromotionBlockers must be empty after evidence attachment")
    return ref


def main() -> int:
    try:
        manifest = load_json(MANIFEST)
        require(manifest.get("apiVersion") == "lattice.socioprophet.dev/v1", "apiVersion mismatch")
        require(manifest.get("kind") == "RuntimePromotionManifest", "kind mismatch")
        metadata = manifest.get("metadata")
        require(isinstance(metadata, dict), "metadata must be object")
        require(metadata.get("version") == "0.2.0", "manifest version must be 0.2.0")
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
        require(policy.get("stablePromotionAllowedWhenAllStableEvidenceGatesPass") is True, "stable allow policy missing")
    except Exception as exc:  # noqa: BLE001
        return fail(str(exc))
    print(json.dumps({"ok": True, "validated": str(MANIFEST)}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
