#!/usr/bin/env python3
"""Validate RuntimeAsset documents.

The validator intentionally remains dependency-light for CI while enforcing the
v1 world-class contract fields: provenance, SBOM, signature, scan,
compatibility, telemetry, and promotion.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

SHA256_RE = re.compile(r"^sha256:[a-fA-F0-9]{64}$")
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{1,62}$")
VERSION_RE = re.compile(r"^v?[0-9]+\.[0-9]+\.[0-9]+([-.+][A-Za-z0-9.-]+)?$")
RUNTIME_CLASSES = {"notebook", "agent", "ray", "beam", "cli", "system-tool", "base-image"}
LANGUAGES = {"python", "r", "go", "rust", "javascript", "typescript", "shell", "sql"}
CHANNEL_TYPES = {"nixpkgs", "conda-forge", "prophet", "pypi", "go-module", "oci", "other"}
BUILD_SYSTEMS = {"nix", "conda-lock", "oci", "script", "mixed"}
ARTIFACT_ROLES = {"nix-closure", "conda-env", "oci-image", "kernel-spec", "sbom", "lockfile", "signature", "attestation", "scan-report", "archive", "other"}
ATTESTATIONS = {"slsa", "in-toto"}
SBOM_FORMATS = {"spdx", "cyclonedx"}
SIGNATURE_TYPES = {"sigstore", "cosign", "minisign", "x509", "other"}
SCAN_RESULTS = {"not-run", "pass", "warn", "fail"}
NETWORK = {"none", "restricted", "full"}
SECRET_SCOPES = {"none", "scoped", "project", "workspace"}
ACCELERATORS = {"cpu", "gpu", "neural-engine", "tpu"}
ISOLATION = {"container", "vm", "layered", "microvm"}
SURFACES = {"jupyter", "ray", "beam", "agentplane", "sourceos-user", "sourceos-agent", "cloudshell-fog", "prophet-platform"}
METRICS = {"build-duration", "scan-duration", "artifact-size", "promotion-result"}
CHANNELS = {"dev", "staging", "stable", "emergency", "deprecated"}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def require_string(value: object, field: str) -> None:
    require(isinstance(value, str) and bool(value), f"{field} must be a non-empty string")


def require_enum_list(values: object, allowed: set[str], field: str) -> None:
    require(isinstance(values, list), f"{field} must be a list")
    require(bool(values), f"{field} must not be empty")
    require(len(values) == len(set(values)), f"{field} must not contain duplicates")
    invalid = sorted(set(values) - allowed)
    require(not invalid, f"{field} contains invalid values: {invalid}")


def validate_document(doc: dict) -> None:
    require(doc.get("apiVersion") == "lattice.socioprophet.dev/v1", "apiVersion must be lattice.socioprophet.dev/v1")
    require(doc.get("kind") == "RuntimeAsset", "kind must be RuntimeAsset")

    metadata = doc.get("metadata")
    require(isinstance(metadata, dict), "metadata must be an object")
    require(NAME_RE.match(metadata.get("name", "")) is not None, "metadata.name is invalid")
    require(VERSION_RE.match(metadata.get("version", "")) is not None, "metadata.version is invalid")
    require_string(metadata.get("createdAt"), "metadata.createdAt")

    spec = doc.get("spec")
    require(isinstance(spec, dict), "spec must be an object")
    require(spec.get("runtimeClass") in RUNTIME_CLASSES, "spec.runtimeClass is invalid")
    require_enum_list(spec.get("languages"), LANGUAGES, "spec.languages")

    channels = spec.get("channels", [])
    require(isinstance(channels, list), "spec.channels must be a list when present")
    for index, channel in enumerate(channels):
        prefix = f"spec.channels[{index}]"
        require(isinstance(channel, dict), f"{prefix} must be an object")
        require_string(channel.get("name"), f"{prefix}.name")
        require(channel.get("type") in CHANNEL_TYPES, f"{prefix}.type is invalid")
        if "trusted" in channel:
            require(isinstance(channel["trusted"], bool), f"{prefix}.trusted must be a boolean")

    build = spec.get("build")
    require(isinstance(build, dict), "spec.build must be an object")
    require(build.get("system") in BUILD_SYSTEMS, "spec.build.system is invalid")
    require_string(build.get("entrypoint"), "spec.build.entrypoint")
    require_string(build.get("builderId"), "spec.build.builderId")

    artifacts = spec.get("artifacts")
    require(isinstance(artifacts, list) and artifacts, "spec.artifacts must be a non-empty list")
    for index, artifact in enumerate(artifacts):
        prefix = f"spec.artifacts[{index}]"
        require(isinstance(artifact, dict), f"{prefix} must be an object")
        require_string(artifact.get("name"), f"{prefix}.name")
        require(artifact.get("role") in ARTIFACT_ROLES, f"{prefix}.role is invalid")
        require(SHA256_RE.match(artifact.get("digest", "")) is not None, f"{prefix}.digest must be sha256:<64 hex chars>")

    provenance = spec.get("provenance")
    require(isinstance(provenance, dict), "spec.provenance must be an object")
    require_enum_list(provenance.get("attestations"), ATTESTATIONS, "spec.provenance.attestations")
    require(isinstance(provenance.get("sourceRefs"), list) and provenance["sourceRefs"], "spec.provenance.sourceRefs must be a non-empty list")
    require_string(provenance.get("builderId"), "spec.provenance.builderId")

    sbom = spec.get("sbom")
    require(isinstance(sbom, dict), "spec.sbom must be an object")
    require_enum_list(sbom.get("formats"), SBOM_FORMATS, "spec.sbom.formats")
    require(SHA256_RE.match(sbom.get("digest", "")) is not None, "spec.sbom.digest must be sha256:<64 hex chars>")

    signature = spec.get("signature")
    require(isinstance(signature, dict), "spec.signature must be an object")
    require(signature.get("type") in SIGNATURE_TYPES, "spec.signature.type is invalid")
    require(SHA256_RE.match(signature.get("digest", "")) is not None, "spec.signature.digest must be sha256:<64 hex chars>")

    scan = spec.get("scan")
    require(isinstance(scan, dict), "spec.scan must be an object")
    require(scan.get("vulnerability") in SCAN_RESULTS, "spec.scan.vulnerability is invalid")
    require(scan.get("license") in SCAN_RESULTS, "spec.scan.license is invalid")
    require(scan.get("policy") in SCAN_RESULTS, "spec.scan.policy is invalid")

    policy = spec.get("policy")
    require(isinstance(policy, dict), "spec.policy must be an object")
    require(policy.get("network") in NETWORK, "spec.policy.network is invalid")
    require(policy.get("secrets") in SECRET_SCOPES, "spec.policy.secrets is invalid")
    require_enum_list(policy.get("accelerators"), ACCELERATORS, "spec.policy.accelerators")
    require(policy.get("defaultIsolation") in ISOLATION, "spec.policy.defaultIsolation is invalid")

    compatibility = spec.get("compatibility")
    require(isinstance(compatibility, dict), "spec.compatibility must be an object")
    require_enum_list(compatibility.get("surfaces"), SURFACES, "spec.compatibility.surfaces")

    telemetry = spec.get("telemetry")
    require(isinstance(telemetry, dict), "spec.telemetry must be an object")
    require(isinstance(telemetry.get("traceRequired"), bool), "spec.telemetry.traceRequired must be a boolean")
    require_enum_list(telemetry.get("metricSet"), METRICS, "spec.telemetry.metricSet")

    promotion = spec.get("promotion")
    require(isinstance(promotion, dict), "spec.promotion must be an object")
    require(promotion.get("channel") in CHANNELS, "spec.promotion.channel is invalid")
    require_string(promotion.get("rollbackRef"), "spec.promotion.rollbackRef")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate RuntimeAsset JSON files")
    parser.add_argument("paths", nargs="+", type=Path)
    args = parser.parse_args(argv)

    failed = False
    for path in args.paths:
        try:
            with path.open("r", encoding="utf-8") as handle:
                validate_document(json.load(handle))
            print(f"PASS {path}")
        except Exception as exc:  # noqa: BLE001
            failed = True
            print(f"FAIL {path}: {exc}", file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
