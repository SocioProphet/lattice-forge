import json
from pathlib import Path

import pytest

from lattice_forge.validate_runtime_asset import main, validate_document

ROOT = Path(__file__).resolve().parents[1]
RUNTIME_ASSET_FIXTURES = [
    ROOT / "examples" / "runtime-asset.example.json",
    ROOT / "runtimes" / "prophet-python-ml" / "runtime-asset.json",
]
REQUIRED_NOTEBOOK_SURFACES = {
    "jupyter",  # legacy compatibility alias
    "jupyterlab",
    "zeppelin",
    "observable",
    "quarto",
    "lattice-studio",
}

CLI_EXAMPLES = [
    ROOT / "examples" / "runtime-asset.gaia-osm-ingest.json",
    ROOT / "examples" / "runtime-asset.notebook-to-artifact.json",
    ROOT / "examples" / "runtime-asset.sourceos-image-build.json",
]


def test_example_runtime_asset_validates() -> None:
    example = ROOT / "examples" / "runtime-asset.example.json"
    assert main([str(example)]) == 0


def test_runtime_asset_fixtures_validate() -> None:
    assert main([str(path) for path in RUNTIME_ASSET_FIXTURES]) == 0


def test_runtime_asset_fixtures_cover_notebook_surface_plane() -> None:
    for fixture in RUNTIME_ASSET_FIXTURES:
        runtime_asset = json.loads(fixture.read_text(encoding="utf-8"))
        assert runtime_asset["spec"]["runtimeClass"] == "notebook"
        surfaces = set(runtime_asset["spec"]["compatibility"]["surfaces"])
        missing = REQUIRED_NOTEBOOK_SURFACES - surfaces
        assert not missing, f"{fixture} is missing required notebook compatibility surfaces: {sorted(missing)}"


def test_cli_examples_validate() -> None:
    """All CLI/system-tool examples including gaia-osm-ingest must validate."""
    assert main([str(p) for p in CLI_EXAMPLES]) == 0


def test_gaia_osm_ingest_labels() -> None:
    fixture = ROOT / "examples" / "runtime-asset.gaia-osm-ingest.json"
    doc = json.loads(fixture.read_text(encoding="utf-8"))
    labels = doc["metadata"]["labels"]
    assert labels["prophetArtifact"] == "gaia.bounded-osm-ingest"
    assert labels["ownerRepo"] == "SocioProphet/gaia-world-model"
    assert labels["safetyClass"] == "bounded"


def test_label_prophet_artifact_valid() -> None:
    base = _minimal_doc()
    base["metadata"]["labels"] = {"prophetArtifact": "gaia.bounded-osm-ingest"}
    validate_document(base)  # must not raise


def test_label_prophet_artifact_invalid() -> None:
    base = _minimal_doc()
    base["metadata"]["labels"] = {"prophetArtifact": "INVALID UPPER"}
    with pytest.raises(ValueError, match="prophetArtifact"):
        validate_document(base)


def test_label_owner_repo_valid() -> None:
    base = _minimal_doc()
    base["metadata"]["labels"] = {"ownerRepo": "SocioProphet/gaia-world-model"}
    validate_document(base)  # must not raise


def test_label_owner_repo_invalid() -> None:
    base = _minimal_doc()
    base["metadata"]["labels"] = {"ownerRepo": "not-a-repo"}
    with pytest.raises(ValueError, match="ownerRepo"):
        validate_document(base)


def test_label_safety_class_valid() -> None:
    base = _minimal_doc()
    for sc in ("bounded", "critical", "experimental", "deprecated"):
        base["metadata"]["labels"] = {"safetyClass": sc}
        validate_document(base)  # must not raise


def test_label_safety_class_invalid() -> None:
    base = _minimal_doc()
    base["metadata"]["labels"] = {"safetyClass": "unknown"}
    with pytest.raises(ValueError, match="safetyClass"):
        validate_document(base)


def test_labels_not_required() -> None:
    """A RuntimeAsset without any labels must still pass validation."""
    base = _minimal_doc()
    assert "labels" not in base["metadata"]
    validate_document(base)  # must not raise


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _minimal_doc() -> dict:
    """Return a valid minimal RuntimeAsset document (notebook class)."""
    return {
        "apiVersion": "lattice.socioprophet.dev/v1",
        "kind": "RuntimeAsset",
        "metadata": {
            "name": "test-runtime",
            "version": "0.1.0",
            "createdAt": "2026-05-08T00:00:00Z",
        },
        "spec": {
            "runtimeClass": "notebook",
            "languages": ["python"],
            "channels": [{"name": "nixpkgs", "type": "nixpkgs", "trusted": True}],
            "build": {
                "system": "nix",
                "entrypoint": "runtimes/test/flake.nix",
                "builderId": "test-builder",
            },
            "artifacts": [
                {"name": "test-image", "role": "oci-image", "digest": "sha256:" + "a" * 64},
            ],
            "provenance": {
                "attestations": ["slsa"],
                "sourceRefs": ["local"],
                "builderId": "test-builder",
            },
            "sbom": {
                "formats": ["spdx"],
                "digest": "sha256:" + "b" * 64,
            },
            "signature": {
                "type": "sigstore",
                "digest": "sha256:" + "c" * 64,
            },
            "scan": {"vulnerability": "not-run", "license": "not-run", "policy": "not-run"},
            "policy": {
                "network": "restricted",
                "secrets": "none",
                "accelerators": ["cpu"],
                "defaultIsolation": "container",
            },
            "compatibility": {"surfaces": ["prophet-platform"]},
            "telemetry": {"traceRequired": True, "metricSet": ["build-duration"]},
            "promotion": {"channel": "dev", "rollbackRef": "runtime/test/0.0.0"},
        },
    }
