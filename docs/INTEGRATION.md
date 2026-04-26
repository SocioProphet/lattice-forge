# Lattice Forge Integration Contract

`lattice-forge` is consumed by Prophet Lattice as the governed runtime and package distribution boundary.

## Upstream dependencies

- `SourceOS-Linux/sourceos-spec`: canonical contract home. RuntimeAsset v0 starts here and should graduate upstream once stable.
- Nix ecosystem: build and pin runtime closures.
- Open conda-compatible ecosystems: user-facing scientific package environments without making Anaconda Distribution the default.

## Downstream consumers

- `SocioProphet/prophet-platform`: runtime catalog, notebook runtime picker, model execution spaces, package governance UI.
- `SocioProphet/agentplane`: execution runtimes, tool images, replayable agent environments.
- `SourceOS-Linux/sourceos-boot`: boot/install/recovery flows can reference runtime artifacts and SBOMs.
- `SocioProphet/cloudshell-fog`: shell runtime images and tool bundles.
- `SocioProphet/sociosphere`: workspace topology and dependency-direction validation.

## Contract handoff

The handoff unit is `RuntimeAsset`.

A Prophet Platform runtime service should be able to:

1. ingest or reference a RuntimeAsset document;
2. verify lockfile, SBOM, image digest, and signature evidence;
3. publish approved runtimes to projects, deployment spaces, notebook kernels, and agent workspaces;
4. require a policy profile for network, secrets, accelerators, and isolation;
5. record runtime use in EvidenceBundle and Factsheet objects.

## Dependency direction

`lattice-forge` may import schemas from `sourceos-spec` once published.

`lattice-forge` must not import notebook UI, catalog service, or AgentPlane execution code.

`prophet-platform`, `agentplane`, and `cloudshell-fog` may consume generated RuntimeAsset metadata and release artifacts from this repo.

## Evidence reports

Minimum evidence reports for demo-grade integration:

- `lockfile-hash`
- `sbom-ref`
- `image-digest`
- `package-manifest`
- `scan-result`
- `signature`
- `builder-id`

## Implementation milestones

1. RuntimeAsset validation.
2. Nix flake runtime scaffold.
3. micromamba/conda-compatible environment lock convention.
4. Jupyter kernel packaging stub.
5. Ray runtime profile.
6. Beam runtime profile.
7. SBOM/signature evidence manifest.
