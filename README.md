# Lattice Forge

Lattice Forge is the governed runtime and package distribution surface for Prophet Lattice.

It owns the build and provenance boundary for reproducible runtimes:

```text
RuntimeAsset -> lockfile/provenance -> build artifact -> signed runtime release
```

Initial scope:

- Nix-managed runtime closures.
- Conda-compatible runtime profiles using open channels.
- Curated Prophet package channels.
- Jupyter kernels and notebook runtime images.
- Ray and Beam execution images.
- SBOMs, lockfiles, signatures, scan records, and promotion evidence.

Integration boundaries:

- `SocioProphet/prophet-platform` owns platform services and control-plane UI.
- `SourceOS-Linux/sourceos-spec` owns canonical schemas and contracts.
- `SocioProphet/agentplane` owns governed execution and replay.
- `SourceOS-Linux/sourceos-boot` owns boot and recovery artifacts.

## Initial implementation

This repo currently provides:

- `schemas/runtime-asset.schema.json` — RuntimeAsset v0 contract.
- `examples/runtime-asset.example.json` — minimal valid runtime example.
- `src/lattice_forge/validate_runtime_asset.py` — zero-dependency validator for CI.
- `.github/workflows/ci.yml` — validation workflow.
