import json
from pathlib import Path

from lattice_forge.evidence_summary import main, summarize


def test_evidence_summary_for_prophet_python_ml() -> None:
    root = Path(__file__).resolve().parents[1]
    runtime_dir = root / "runtimes" / "prophet-python-ml"
    summary = summarize(runtime_dir)

    assert summary["kind"] == "RuntimeEvidenceSummary"
    assert summary["runtime"]["name"] == "prophet-python-ml"
    assert summary["evidence"]["kernel"]["present"] is True
    assert summary["evidence"]["sbom"]["present"] is True
    assert summary["evidence"]["provenance"]["present"] is True
    assert summary["evidence"]["scan"]["present"] is True


def test_evidence_summary_cli(capsys) -> None:
    root = Path(__file__).resolve().parents[1]
    runtime_dir = root / "runtimes" / "prophet-python-ml"
    assert main([str(runtime_dir)]) == 0
    emitted = json.loads(capsys.readouterr().out)
    assert emitted["kind"] == "RuntimeEvidenceSummary"
