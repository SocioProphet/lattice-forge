from pathlib import Path

from lattice_forge.validate_runtime_asset import main


def test_example_runtime_asset_validates() -> None:
    root = Path(__file__).resolve().parents[1]
    example = root / "examples" / "runtime-asset.example.json"
    assert main([str(example)]) == 0
