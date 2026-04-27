# World-Class Target Architecture: Lattice Forge

This repo is not allowed to stop at basic runtime metadata. `lattice-forge` must become a world-class reproducible runtime, package, kernel, and image foundry for Prophet Lattice and SourceOS.

## State-of-the-art bar

Lattice Forge must align with these target classes:

1. **Reproducible runtime construction**
   - Nix-first lifecycle governance for system, user, notebook, agent, Ray, Beam, and CLI runtimes.
   - Conda-compatible user ergonomics without defaulting to commercial Anaconda Distribution channels.
   - Lockfiles, pinned inputs, closure hashes, and cache provenance for every runtime.

2. **Software supply-chain security**
   - SLSA provenance for every runtime artifact.
   - in-toto attestations for build, test, scan, sign, and promote steps.
   - Sigstore/cosign signing for OCI images, SBOMs, package manifests, runtime manifests, and kernel specs.
   - Transparency-log verification where available.

3. **SBOM and package intelligence**
   - SPDX and CycloneDX output support.
   - Package manifests for Python, R, Go, Rust, JS/TS, system tools, notebook extensions, Ray, Beam, and agent tools.
   - Vulnerability scan evidence and license posture attached to RuntimeAsset.
   - AI/ML BOM support for models, datasets, vector indexes, prompts, and agent toolchains when runtime artifacts package AI assets.

4. **Runtime policy and isolation**
   - Every RuntimeAsset declares network, secrets, accelerators, filesystem, and default isolation posture.
   - Runtime promotion must be blocked if policy posture is incomplete.
   - GPU/accelerator support must be explicit and auditable.

5. **Notebook and MLOps integration**
   - Notebook runtimes must be adapter-based and must not hard-code Jupyter as the ontology.
   - Jupyter/JupyterLab kernels must remain first-class artifacts.
   - Apache Zeppelin runtime compatibility must be modeled for collaborative analytics, Spark, SQL, Scala, Python, and R workflows.
   - Observable runtime compatibility must be modeled for browser-native reactive visualization and data storytelling.
   - Pluto.jl runtime compatibility must be modeled for Julia/reactive scientific notebook workflows.
   - Quarto runtime compatibility must be modeled for reproducible technical publishing, dashboards, books, slides, and notebook-derived reports.
   - Ray runtime environments must be cataloged and evidence-producing.
   - Beam runtime profiles must be cataloged and evidence-producing.
   - Runtime use must link to NotebookSession, NotebookSurfacePlane, ExperimentRun, PipelineRun, ModelAsset, AgentAsset, and EvidenceBundle objects.

6. **Catalog integration**
   - RuntimeAsset must be consumable by Prophet Platform as a governed catalog object.
   - RuntimeAsset must declare compatible project types, deployment spaces, and execution surfaces.
   - Runtime usage must be searchable, auditable, and factsheet-linked.

7. **Observability**
   - OpenTelemetry-compatible traces, metrics, and logs for build services and runtime publication services.
   - Runtime evidence must correlate with release, project, job, agent, model, and data-product IDs.

8. **Operational release discipline**
   - Channels: dev, staging, stable, emergency, deprecated.
   - Promotion requires passing validation, provenance, SBOM, scan, policy, and signature gates.
   - Rollback must be possible by artifact digest, not mutable tag.

## Non-negotiable product invariant

A Lattice runtime is not valid unless it can answer:

- what packages it contains;
- which sources produced them;
- which lockfiles pinned them;
- which builder built it;
- which scans passed or failed;
- which SBOM describes it;
- which policy allows it;
- which signature proves it;
- which notebook, agent, Ray, Beam, shell, or platform surface can consume it;
- where it was used;
- and how to reproduce or roll it back.

## Current notebook surface contract

`RuntimeAsset.spec.compatibility.surfaces` must support the Lattice Studio adapter plane. The required notebook/workbench surface set is:

- `jupyter` as the legacy compatibility alias for existing runtime payloads.
- `jupyterlab` as the default scientific notebook adapter.
- `zeppelin` for collaborative analytics and data-lake/Spark/SQL workflows.
- `observable` for browser-native reactive visualization and data storytelling.
- `plutojl` for Julia/reactive scientific computing.
- `quarto` for reproducible technical publishing and notebook-derived reports.
- `lattice-studio` for the governed workbench surface that binds RuntimeAsset, NotebookSession, catalog inputs, policies, and evidence.

Producer-side tests in this repo and consumer-side tests in `SocioProphet/prophet-platform` must prevent the notebook adapter set from drifting out of sync.

## Contract upgrades required

RuntimeAsset v1 must add or preserve:

- `provenance`: SLSA/in-toto references, builder identity, source commits, resolved inputs.
- `sbom`: SPDX/CycloneDX references and digest fields.
- `signature`: Sigstore/cosign bundle or production signing reference.
- `scan`: vulnerability, license, and policy scan summaries.
- `compatibility`: Jupyter/JupyterLab, Zeppelin, Observable, Pluto.jl, Quarto, Lattice Studio, Ray, Beam, agent, SourceOS user-plane, SourceOS agent-plane compatibility.
- `telemetry`: OpenTelemetry trace context and evidence correlation IDs.
- `promotion`: channel, approvals, expiry, deprecation, rollback target.

## Implementation path

1. Keep v1 validator simple and stable.
2. Add Nix flake runtime scaffold.
3. Add conda-compatible environment lock convention.
4. Add SBOM manifest schema.
5. Add SLSA/in-toto provenance references.
6. Add Sigstore/cosign bundle references.
7. Add JupyterLab kernel package stub.
8. Add Zeppelin, Observable, Pluto.jl, and Quarto adapter runtime descriptors.
9. Add Ray and Beam runtime profiles.
10. Add RuntimeAsset evidence emitter.
11. Add cross-repo fixture drift checks against Prophet Platform/Lattice Studio.

## Doctrine

Lattice is the control plane. SourceOS is the substrate. Fog is where execution happens.

`lattice-forge` must make every runtime reproducible, governable, auditable, and safe to promote.
