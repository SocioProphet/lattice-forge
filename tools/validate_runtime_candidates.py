#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path

REQUIRED_FIELDS = [
    "candidate_version",
    "runtime_id",
    "runtime_name",
    "admission_state",
    "admitted",
    "owning_domain",
    "implementation_repo",
    "entrypoint",
    "validation_command",
    "ci_workflow_ref",
    "input_fixture_ref",
    "output_schema_ref",
    "runtime_boundary_ref",
    "standards_refs",
    "evidence_contract",
    "negative_tests",
    "remaining_admission_requirements",
    "safety_boundary",
]
REQUIRED_STANDARDS = {
    "SocioProphet/prophet-platform-standards/docs/standards/070-multidomain-geospatial-standards-alignment.md",
    "SocioProphet/socioprophet-standards-storage/docs/standards/096-multidomain-geospatial-storage-contracts.md",
    "SocioProphet/socioprophet-standards-knowledge/docs/standards/080-multidomain-geospatial-knowledge-context.md",
    "SocioProphet/socioprophet-agent-standards/docs/standards/020-multidomain-geospatial-agent-runtime.md",
}


def fail(msg: str) -> None:
    print(f"ERR: {msg}", file=sys.stderr)
    raise SystemExit(2)


def load_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        fail(f"{path}: invalid JSON: {exc}")
    if not isinstance(data, dict):
        fail(f"{path}: expected object")
    return data


def require_keys(path: Path, data: dict, keys: list[str]) -> None:
    missing = [key for key in keys if key not in data]
    if missing:
        fail(f"{path}: missing required keys: {', '.join(missing)}")


def validate_candidate(path: Path) -> None:
    data = load_json(path)
    require_keys(path, data, REQUIRED_FIELDS)
    state = data["admission_state"]
    if state not in {"candidate", "blocked", "admitted"}:
        fail(f"{path}: invalid admission_state {state!r}")
    if state == "candidate" and data.get("admitted") is not False:
        fail(f"{path}: candidate records must set admitted=false")
    if state != "admitted" and not data.get("remaining_admission_requirements"):
        fail(f"{path}: non-admitted records must list remaining_admission_requirements")
    refs = set(data.get("standards_refs", []))
    missing_standards = sorted(REQUIRED_STANDARDS - refs)
    if missing_standards:
        fail(f"{path}: missing standards refs: {', '.join(missing_standards)}")
    evidence = data.get("evidence_contract")
    if not isinstance(evidence, dict):
        fail(f"{path}: evidence_contract must be object")
    for key in ["emits_runtime_evidence", "input_manifest", "output_manifest", "policy_posture", "replay_command"]:
        if evidence.get(key) is not True:
            fail(f"{path}: evidence_contract.{key} must be true")
    safety = data.get("safety_boundary")
    if not isinstance(safety, dict):
        fail(f"{path}: safety_boundary must be object")
    if safety.get("network_posture") != "none_for_fixture_proof":
        fail(f"{path}: fixture candidates must declare network_posture=none_for_fixture_proof")
    if safety.get("secret_posture") != "none_for_fixture_proof":
        fail(f"{path}: fixture candidates must declare secret_posture=none_for_fixture_proof")


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    candidates = sorted((root / "registry/runtime-candidates").glob("*.json"))
    if not candidates:
        fail("no runtime candidate records found")
    for candidate in candidates:
        validate_candidate(candidate)
    print(f"OK: validated {len(candidates)} runtime candidate record(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
