#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNTIME_DIR = ROOT / "runtimes" / "prophet-python-ml"
BUILD_DIR = ROOT / "build" / "runtime-assets"


def digest_file(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def artifact(path: Path, role: str, media_type: str) -> dict:
    rel = path.relative_to(ROOT).as_posix()
    return {
        "name": rel,
        "role": role,
        "digest": digest_file(path),
        "uri": rel,
        "mediaType": media_type,
    }


def runtime_asset() -> dict:
    flake = RUNTIME_DIR / "flake.nix"
    lock = RUNTIME_DIR / "conda-lock.yml"
    kernel = RUNTIME_DIR / "kernel.json"
    artifacts = [
        artifact(flake, "nix-closure", "text/x-nix"),
        artifact(lock, "lockfile", "application/x-yaml"),
        artifact(kernel, "kernel-spec", "application/json"),
    ]
    sbom_digest = "sha256:" + hashlib.sha256(json.dumps(artifacts, sort_keys=True).encode("utf-8")).hexdigest()
    return {
        "apiVersion": "lattice.socioprophet.dev/v1",
        "kind": "RuntimeAsset",
        "metadata": {
            "name": "prophet-python-ml",
            "version": "0.1.0",
            "createdAt": "2026-05-01T19:00:00Z",
            "labels": {"lane": "lattice-studio-data-governai"},
        },
        "spec": {
            "runtimeClass": "notebook",
            "languages": ["python", "sql"],
            "channels": [
                {"name": "nixpkgs", "type": "nixpkgs", "trusted": True},
                {"name": "conda-forge", "type": "conda-forge", "trusted": True},
                {"name": "prophet-core", "type": "prophet", "trusted": True},
            ],
            "build": {
                "system": "mixed",
                "entrypoint": "runtimes/prophet-python-ml/flake.nix",
                "lockfile": "runtimes/prophet-python-ml/conda-lock.yml",
                "sourceRef": "SocioProphet/lattice-forge",
                "builderId": "lattice-forge-demo-builder",
            },
            "artifacts": artifacts,
            "provenance": {
                "attestations": ["slsa", "in-toto"],
                "sourceRefs": ["SocioProphet/lattice-forge"],
                "builderId": "lattice-forge-demo-builder",
            },
            "sbom": {"formats": ["spdx"], "digest": sbom_digest, "uri": "build/runtime-assets/prophet-python-ml.sbom.spdx.json"},
            "signature": {"type": "sigstore", "bundleRef": "build/runtime-assets/prophet-python-ml.sigstore.bundle", "digest": sbom_digest},
            "scan": {"vulnerability": "not-run", "license": "not-run", "policy": "not-run"},
            "policy": {"network": "restricted", "secrets": "scoped", "accelerators": ["cpu"], "defaultIsolation": "container"},
            "compatibility": {
                "surfaces": ["jupyter", "jupyterlab", "lattice-studio", "ray", "beam", "agentplane", "sourceos-user", "prophet-platform"]
            },
            "telemetry": {"traceRequired": True, "metricSet": ["build-duration", "scan-duration", "artifact-size", "promotion-result"]},
            "promotion": {"channel": "dev", "rollbackRef": "runtime/prophet-python-ml/0.0.1"},
        },
    }


def main() -> int:
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    output = BUILD_DIR / "prophet-python-ml.runtime-asset.json"
    output.write_text(json.dumps(runtime_asset(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"written": [str(output)]}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
