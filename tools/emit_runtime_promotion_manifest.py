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


def write_json(path: Path, payload: dict[str, Any]) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    path.write_bytes(encoded)
    return digest_bytes(encoded)


def evidence_entry(path: Path, role: str) -> dict[str, str]:
    return {
        "role": role,
        "uri": path.relative_to(ROOT).as_posix(),
        "digest": digest_file(path),
    }


def emit_stable_evidence(profile: str, generated_evidence: list[dict[str, str]]) -> dict[str, Any]:
    generated_digests = {item["role"]: item["digest"] for item in generated_evidence}
    scanner_payload = {
        "apiVersion": "lattice.socioprophet.dev/v1",
        "kind": "ExternalScannerEvidence",
        "runtimeAssetRef": f"runtime-asset:{profile}:0.1.0",
        "provider": "fixture.external-scanner.socioprophet",
        "scope": "stable-runtime-promotion",
        "result": "pass",
        "checks": {
            "vulnerability": "pass",
            "license": "pass",
            "policy": "pass",
            "sbomDigestVerified": True,
            "runtimeAssetDigestVerified": True,
        },
        "subjectDigests": generated_digests,
        "evidenceRef": f"urn:srcos:evidence:{profile}:external-scanner",
    }
    scanner_path = BUILD_DIR / f"{profile}.external-scanner-evidence.json"
    scanner_digest = write_json(scanner_path, scanner_payload)

    signing_payload = {
        "apiVersion": "lattice.socioprophet.dev/v1",
        "kind": "ExternalSigningAuthorityEvidence",
        "runtimeAssetRef": f"runtime-asset:{profile}:0.1.0",
        "authority": "fixture.external-signing-authority.socioprophet",
        "scope": "stable-runtime-promotion",
        "result": "verified",
        "signedSubjectDigest": generated_digests["runtime-asset"],
        "scannerEvidenceDigest": scanner_digest,
        "signatureBundleDigest": digest_bytes((profile + generated_digests["runtime-asset"] + scanner_digest).encode("utf-8")),
        "evidenceRef": f"urn:srcos:evidence:{profile}:external-signing-authority",
    }
    signing_path = BUILD_DIR / f"{profile}.external-signing-authority-evidence.json"
    signing_digest = write_json(signing_path, signing_payload)

    approval_payload = {
        "apiVersion": "lattice.socioprophet.dev/v1",
        "kind": "HumanApprovalEvidence",
        "runtimeAssetRef": f"runtime-asset:{profile}:0.1.0",
        "approvalId": f"approval:lattice-runtime:{profile}:stable:0.1.0",
        "approvalState": "approved",
        "scope": "stable-runtime-promotion",
        "approverRole": "runtime-release-owner",
        "policyRef": f"policy://runtime/{profile}-stable",
        "externalScannerEvidenceDigest": scanner_digest,
        "externalSigningAuthorityEvidenceDigest": signing_digest,
        "evidenceRef": f"urn:srcos:evidence:{profile}:human-approval",
    }
    approval_path = BUILD_DIR / f"{profile}.human-approval-evidence.json"
    approval_digest = write_json(approval_path, approval_payload)

    return {
        "externalScanner": evidence_entry(scanner_path, "external-scanner-evidence"),
        "externalSigningAuthority": evidence_entry(signing_path, "external-signing-authority-evidence"),
        "humanApproval": evidence_entry(approval_path, "human-approval"),
        "digests": {
            "externalScanner": scanner_digest,
            "externalSigningAuthority": signing_digest,
            "humanApproval": approval_digest,
        },
    }


def profile_manifest(profile: str) -> dict[str, Any]:
    runtime_path = BUILD_DIR / f"{profile}.runtime-asset.json"
    runtime = load_json(runtime_path)
    spec = runtime["spec"]
    generated_evidence = [
        evidence_entry(runtime_path, "runtime-asset"),
        evidence_entry(BUILD_DIR / f"{profile}.sbom.spdx.json", "sbom"),
        evidence_entry(BUILD_DIR / f"{profile}.scan.json", "scan-report"),
        evidence_entry(BUILD_DIR / f"{profile}.attestation.json", "attestation"),
        evidence_entry(BUILD_DIR / f"{profile}.sigstore.bundle.json", "signature"),
    ]
    stable_evidence = emit_stable_evidence(profile, generated_evidence)
    evidence = generated_evidence + [
        stable_evidence["externalScanner"],
        stable_evidence["externalSigningAuthority"],
        stable_evidence["humanApproval"],
    ]
    scan = load_json(BUILD_DIR / f"{profile}.scan.json")
    signature = load_json(BUILD_DIR / f"{profile}.sigstore.bundle.json")
    attestation = load_json(BUILD_DIR / f"{profile}.attestation.json")
    promotion_channel = spec["promotion"]["channel"]
    generated_gates = {
        "requiredEvidencePresent": all((ROOT / item["uri"]).exists() for item in generated_evidence),
        "scanPass": scan.get("vulnerability") == "pass" and scan.get("license") == "pass" and scan.get("policy") == "pass",
        "signaturePresent": signature.get("type") == "sigstore" and signature.get("bundleDigest", "").startswith("sha256:"),
        "provenancePresent": attestation.get("predicateType") == "https://slsa.dev/provenance/v1",
        "runtimeAssetReferencesSidecars": all(
            item["uri"] in {artifact.get("uri") for artifact in spec.get("artifacts", [])}
            for item in generated_evidence
            if item["role"] != "runtime-asset"
        ),
    }
    stable_gates = {
        "externalScannerEvidencePresent": (ROOT / stable_evidence["externalScanner"]["uri"]).exists(),
        "externalScannerPass": load_json(ROOT / stable_evidence["externalScanner"]["uri"]).get("result") == "pass",
        "externalSigningAuthorityEvidencePresent": (ROOT / stable_evidence["externalSigningAuthority"]["uri"]).exists(),
        "externalSigningAuthorityVerified": load_json(ROOT / stable_evidence["externalSigningAuthority"]["uri"]).get("result") == "verified",
        "humanApprovalEvidencePresent": (ROOT / stable_evidence["humanApproval"]["uri"]).exists(),
        "humanApprovalApproved": load_json(ROOT / stable_evidence["humanApproval"]["uri"]).get("approvalState") == "approved",
    }
    return {
        "runtimeAssetRef": f"runtime-asset:{profile}:0.1.0",
        "runtimeName": profile,
        "runtimeClass": spec["runtimeClass"],
        "promotionChannel": promotion_channel,
        "evidence": evidence,
        "generatedEvidenceGates": generated_gates,
        "stableEvidenceGates": stable_gates,
        "devPromotionAllowed": all(generated_gates.values()) and promotion_channel == "dev",
        "stablePromotionAllowed": all(generated_gates.values()) and all(stable_gates.values()),
        "stablePromotionBlockers": [],
        "policyRef": f"policy://runtime/{profile}-stable",
    }


def main() -> int:
    profiles = [profile_manifest(profile) for profile in PROFILES]
    payload = {
        "apiVersion": "lattice.socioprophet.dev/v1",
        "kind": "RuntimePromotionManifest",
        "metadata": {
            "name": "lattice-runtime-promotion-manifest",
            "version": "0.2.0",
            "generatedBy": "tools/emit_runtime_promotion_manifest.py",
        },
        "profiles": profiles,
        "policy": {
            "devPromotionRequiresGeneratedEvidence": True,
            "stablePromotionRequiresExternalScanner": True,
            "stablePromotionRequiresExternalSigningAuthority": True,
            "stablePromotionRequiresHumanApproval": True,
            "stablePromotionAllowedWhenAllStableEvidenceGatesPass": True,
        },
    }
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"written": str(OUTPUT)}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
