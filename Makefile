.PHONY: validate runtime-candidates-validate runtime-asset-emit runtime-asset-validate runtime-sidecars-validate runtime-promotion-manifest-emit runtime-promotion-manifest-validate

validate: runtime-candidates-validate runtime-asset-validate runtime-sidecars-validate runtime-promotion-manifest-validate
	@echo "OK: validate"

runtime-candidates-validate:
	./.venv/bin/python tools/validate_runtime_candidates.py 2>/dev/null || python3 tools/validate_runtime_candidates.py

runtime-asset-emit:
	./.venv/bin/python tools/emit_runtime_asset.py 2>/dev/null || python3 tools/emit_runtime_asset.py

runtime-asset-validate: runtime-asset-emit
	./.venv/bin/python src/lattice_forge/validate_runtime_asset.py \
		examples/runtime-asset.example.json \
		build/runtime-assets/prophet-python-ml.runtime-asset.json \
		build/runtime-assets/prophet-ray-ml.runtime-asset.json \
		build/runtime-assets/prophet-beam-dataops.runtime-asset.json \
		2>/dev/null || python3 src/lattice_forge/validate_runtime_asset.py \
		examples/runtime-asset.example.json \
		build/runtime-assets/prophet-python-ml.runtime-asset.json \
		build/runtime-assets/prophet-ray-ml.runtime-asset.json \
		build/runtime-assets/prophet-beam-dataops.runtime-asset.json

runtime-sidecars-validate: runtime-asset-emit
	./.venv/bin/python tools/validate_runtime_sidecars.py 2>/dev/null || python3 tools/validate_runtime_sidecars.py

runtime-promotion-manifest-emit: runtime-asset-emit
	./.venv/bin/python tools/emit_runtime_promotion_manifest.py 2>/dev/null || python3 tools/emit_runtime_promotion_manifest.py

runtime-promotion-manifest-validate: runtime-promotion-manifest-emit
	./.venv/bin/python tools/validate_runtime_promotion_manifest.py 2>/dev/null || python3 tools/validate_runtime_promotion_manifest.py
