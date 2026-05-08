import json
from pathlib import Path

from lattice_forge.emit_runtime_profile import emit_profile, main

ROOT = Path(__file__).resolve().parents[1]


def _load(name: str) -> dict:
    return json.loads((ROOT / "examples" / name).read_text(encoding="utf-8"))


def test_emit_profile_gaia_osm_ingest() -> None:
    doc = _load("runtime-asset.gaia-osm-ingest.json")
    profile = emit_profile(doc)

    assert profile["apiVersion"] == "lattice.socioprophet.dev/v1"
    assert profile["kind"] == "RuntimeProfile"
    assert profile["profile"] == "lattice-forge/gaia-osm-ingest:0.1.0"
    assert profile["prophetArtifact"] == "gaia.bounded-osm-ingest"
    assert profile["ownerRepo"] == "SocioProphet/gaia-world-model"
    assert profile["safetyClass"] == "bounded"
    assert profile["runtimeClass"] == "cli"
    assert "python" in profile["languages"]
    assert profile["policy"]["network"] == "restricted"
    assert profile["promotionChannel"] == "dev"
    assert isinstance(profile["artifactDigests"], dict)
    assert len(profile["artifactDigests"]) == 3


def test_emit_profile_notebook_to_artifact() -> None:
    doc = _load("runtime-asset.notebook-to-artifact.json")
    profile = emit_profile(doc)

    assert profile["profile"] == "lattice-forge/notebook-to-artifact:0.1.0"
    assert profile["prophetArtifact"] == "prophet.notebook-promotion"
    assert profile["ownerRepo"] == "SocioProphet/prophet-platform"
    assert profile["safetyClass"] == "bounded"


def test_emit_profile_sourceos_image_build() -> None:
    doc = _load("runtime-asset.sourceos-image-build.json")
    profile = emit_profile(doc)

    assert profile["profile"] == "lattice-forge/sourceos-image-build:0.1.0"
    assert profile["prophetArtifact"] == "sourceos.image-build"
    assert profile["ownerRepo"] == "SourceOS-Linux/sourceos-boot"
    assert profile["safetyClass"] == "critical"
    assert profile["policy"]["network"] == "none"
    assert profile["policy"]["defaultIsolation"] == "vm"


def test_emit_profile_no_labels() -> None:
    """RuntimeAsset without labels produces a profile without optional fields."""
    doc = _load("runtime-asset.example.json")
    profile = emit_profile(doc)

    assert profile["kind"] == "RuntimeProfile"
    assert "prophetArtifact" not in profile
    assert "ownerRepo" not in profile
    assert "safetyClass" not in profile


def test_emit_profile_cli_stdout(capsys) -> None:
    fixture = ROOT / "examples" / "runtime-asset.gaia-osm-ingest.json"
    rc = main([str(fixture)])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["kind"] == "RuntimeProfile"
    assert out["profile"] == "lattice-forge/gaia-osm-ingest:0.1.0"


def test_emit_profile_cli_output_file(tmp_path) -> None:
    fixture = ROOT / "examples" / "runtime-asset.gaia-osm-ingest.json"
    out_file = tmp_path / "profile.json"
    rc = main([str(fixture), "--output", str(out_file)])
    assert rc == 0
    assert out_file.exists()
    profile = json.loads(out_file.read_text(encoding="utf-8"))
    assert profile["profile"] == "lattice-forge/gaia-osm-ingest:0.1.0"
