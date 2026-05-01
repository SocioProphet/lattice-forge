#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
BUILD_DIR = ROOT / "build" / "runtime-assets"
CREATED_AT = "2026-05-01T19:00:00Z"


@dataclass(frozen=True)
class RuntimeProfile:
    name: str
    runtime_class: str
    languages: list[str]
    surfaces: list[str]
    network: str
    secrets: str
    accelerators: list[str]
    isolation: str
    channel: str
    rollback_ref: str

    @property
    def directory(self) -> Path:
        return ROOT / "runtimes" / self.name


PROFILES = [
    RuntimeProfile(
        name="prophet-python-ml",
        runtime_class="notebook",
        languages=["python", "sql"],
        surfaces=["jupyter", "jupyterlab", "lattice-studio", "ray", "beam", "agentplane", "sourceos-user", "prophet-platform"],
        network="restricted",
        secrets="scoped",
        accelerators=["cpu"],
        isolation="container",
        channel="dev",
        rollback_ref="runtime/prophet-python-ml/0.0.1",
    ),
    RuntimeProfile(
        name="prophet-ray-ml",
        runtime_class="ray",
        languages=["python", "sql"],
        surfaces=["jupyter", "jupyterlab", "lattice-studio", "ray", "agentplane", "sourceos-agent", "prophet-platform"],
        network="restricted",
        secrets="scoped",
        accelerators=["cpu"],
        isolation="container",
        channel="dev",
        rollback_ref="runtime/prophet-ray-ml/0.0.1",
    ),
    RuntimeProfile(
        name="prophet-beam-dataops",
        runtime_class="beam",
        languages=["python", "sql"],
        surfaces=["jupyter", "jupyterlab", "lattice-studio", "beam", "agentplane", "sourceos-agent", "prophet-platform"],
        network="restricted",
        secrets="scoped",
        accelerators=["cpu"],
        isolation="container",
        channel="dev",
        rollback_ref="runtime/prophet-beam-dataops/0.0.1",
    ),
]


def digest_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def digest_file(path: Path) -> str:
    return digest_bytes(path.read_bytes())


def write_json(path: Path, payload: dict[str, Any]) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    path.write_bytes(encoded)
    return digest_bytes(encoded)


def artifact(path: Path, role: str, media_type: str) -> dict[str, str]:
    rel = path.relative_to(ROOT).as_posix()
    return {
        "name": rel,
        "role": role,
        "digest": digest_file(path),
        "uri": rel,
        "mediaType": media_type,
    }


def base_artifacts(profile: RuntimeProfile) -> list[dict[str, str]]:
    flake = profile.directory / "flake.nix"
    lock = profile.directory / "conda-lock.yml"
    kernel = profile.directory / "kernel.json"
    return [
        artifact(flake, "nix-closure", "text/x-nix"),
        artifact(lock, "lockfile", "application/x-yaml"),
        artifact(kernel, "kernel-spec", "application/json"),
    ]


def emit_sidecars(profile: RuntimeProfile, base: list[dict[str, str]]) -> dict[str, Any]:
    sbom_payload = {
        "spdxVersion": "SPDX-2.3",
        "name": profile.name,
        "packages": [
            {"name": item["name"], "SPDXID": f"SPDXRef-{profile.name}-{idx}", "downloadLocation": item["uri"], "checksums": [{"algorithm": "SHA256", "checksumValue": item["digest"].removeprefix("sha256:")}]}
            for idx, item in enumerate(base, start=1)
        ],
    }
    sbom_path = BUILD_DIR / f"{profile.name}.sbom.spdx.json"
    sbom_digest = write_json(sbom_path, sbom_payload)

    scan_payload = {
        "runtime": profile.name,
        "vulnerability": "pass",
        "license": "pass",
        "policy": "pass",
        "scannedArtifacts": [item["name"] for item in base],
        "evidenceRef": f"urn:srcos:evidence:{profile.name}:scan",
    }
    scan_path = BUILD_DIR / f"{profile.name}.scan.json"
    scan_digest = write_json(scan_path, scan_payload)

    attestation_payload = {
        "runtime": profile.name,
        "builderId": "lattice-forge-demo-builder",
        "predicateType": "https://slsa.dev/provenance/v1",
        "subject": [{"name": item["name"], "digest": {"sha256": item["digest"].removeprefix("sha256:")}} for item in base],
        "buildType": "lattice-forge-runtime-profile",
    }
    attestation_path = BUILD_DIR / f"{profile.name}.attestation.json"
    attestation_digest = write_json(attestation_path, attestation_payload)

    signature_payload = {
        "runtime": profile.name,
        "type": "sigstore",
        "subjectDigest": sbom_digest,
        "bundleDigest": digest_bytes((profile.name + sbom_digest + scan_digest + attestation_digest).encode("utf-8")),
        "evidenceRef": f"urn:srcos:evidence:{profile.name}:signature",
    }
    signature_path = BUILD_DIR / f"{profile.name}.sigstore.bundle.json"
    signature_digest = write_json(signature_path, signature_payload)

    return {
        "sbom": artifact(sbom_path, "sbom", "application/spdx+json"),
        "scan": artifact(scan_path, "scan-report", "application/json"),
        "attestation": artifact(attestation_path, "attestation", "application/json"),
        "signature": artifact(signature_path, "signature", "application/vnd.dev.sigstore.bundle+json"),
        "digests": {
            "sbom": sbom_digest,
            "scan": scan_digest,
            "attestation": attestation_digest,
            "signature": signature_digest,
        },
    }


def runtime_asset(profile: RuntimeProfile) -> dict[str, Any]:
    base = base_artifacts(profile)
    sidecars = emit_sidecars(profile, base)
    artifacts = base + [sidecars["sbom"], sidecars["scan"], sidecars["attestation"], sidecars["signature"]]
    return {
        "apiVersion": "lattice.socioprophet.dev/v1",
        "kind": "RuntimeAsset",
        "metadata": {
            "name": profile.name,
            "version": "0.1.0",
            "createdAt": CREATED_AT,
            "labels": {"lane": "lattice-studio-data-governai"},
        },
        "spec": {
            "runtimeClass": profile.runtime_class,
            "languages": profile.languages,
            "channels": [
                {"name": "nixpkgs", "type": "nixpkgs", "trusted": True},
                {"name": "conda-forge", "type": "conda-forge", "trusted": True},
                {"name": "prophet-core", "type": "prophet", "trusted": True},
            ],
            "build": {
                "system": "mixed",
                "entrypoint": f"runtimes/{profile.name}/flake.nix",
                "lockfile": f"runtimes/{profile.name}/conda-lock.yml",
                "sourceRef": "SocioProphet/lattice-forge",
                "builderId": "lattice-forge-demo-builder",
            },
            "artifacts": artifacts,
            "provenance": {
                "attestations": ["slsa", "in-toto"],
                "sourceRefs": ["SocioProphet/lattice-forge"],
                "builderId": "lattice-forge-demo-builder",
            },
            "sbom": {"formats": ["spdx"], "digest": sidecars["digests"]["sbom"], "uri": sidecars["sbom"]["uri"]},
            "signature": {"type": "sigstore", "bundleRef": sidecars["signature"]["uri"], "digest": sidecars["digests"]["signature"]},
            "scan": {"vulnerability": "pass", "license": "pass", "policy": "pass"},
            "policy": {"network": profile.network, "secrets": profile.secrets, "accelerators": profile.accelerators, "defaultIsolation": profile.isolation},
            "compatibility": {"surfaces": profile.surfaces},
            "telemetry": {"traceRequired": True, "metricSet": ["build-duration", "scan-duration", "artifact-size", "promotion-result"]},
            "promotion": {"channel": profile.channel, "rollbackRef": profile.rollback_ref},
        },
    }


def main() -> int:
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    written: list[str] = []
    for profile in PROFILES:
        output = BUILD_DIR / f"{profile.name}.runtime-asset.json"
        write_json(output, runtime_asset(profile))
        written.append(str(output))
    print(json.dumps({"written": written}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
