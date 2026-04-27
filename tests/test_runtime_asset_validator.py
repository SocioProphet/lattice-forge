import json
from pathlib import Path

from lattice_forge.validate_runtime_asset import main

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
