.PHONY: validate runtime-candidates-validate

validate: runtime-candidates-validate
	@echo "OK: validate"

runtime-candidates-validate:
	./.venv/bin/python tools/validate_runtime_candidates.py 2>/dev/null || python3 tools/validate_runtime_candidates.py
