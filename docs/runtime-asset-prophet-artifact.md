# RuntimeAsset → ProphetArtifact → Evidence Bundle

This document explains how Lattice Forge binds `RuntimeAsset` profiles to
`ProphetArtifact` execution contracts and how artifact runners on Prophet
Platform resolve and consume runtime profiles.

## Overview

The Prophet Computational Knowledge Plane requires that every `ProphetArtifact`
execution is reproducible.  Lattice Forge provides the *runtime substrate* side
of this contract through `RuntimeAsset` documents that carry:

1. **ProphetArtifact binding** — `metadata.labels.prophetArtifact` names the
   artifact execution contract this runtime backs.
2. **Owner repository** — `metadata.labels.ownerRepo` links back to the source
   repository that owns the `ProphetArtifact`.
3. **Safety class** — `metadata.labels.safetyClass` gates which execution
   contexts are allowed to launch the artifact runner.
4. **Execution policy** — `spec.policy` defines network, secrets, accelerator,
   and isolation requirements enforced at runner launch.
5. **Evidence bundle** — SBOM, signature, provenance, and scan fields provide
   the full audit trail from source to running container.

## Runtime profile reference format

A Prophet Platform runner resolves a runtime by its *profile reference*:

```
runtime.profile: lattice-forge/<name>:<version>
```

Examples:

| Profile reference                             | RuntimeAsset name          | ProphetArtifact              |
|-----------------------------------------------|----------------------------|------------------------------|
| `lattice-forge/gaia-osm-ingest:0.1.0`         | `gaia-osm-ingest`          | `gaia.bounded-osm-ingest`    |
| `lattice-forge/notebook-to-artifact:0.1.0`    | `notebook-to-artifact`     | `prophet.notebook-promotion` |
| `lattice-forge/sourceos-image-build:0.1.0`    | `sourceos-image-build`     | `sourceos.image-build`       |

## How artifact runners resolve a runtime profile

1. **Lookup** — The runner reads `runtime.profile` from its execution manifest
   and fetches the corresponding `RuntimeAsset` from the Lattice Forge registry.

2. **Emit RuntimeProfile** — The runner (or a CI step) calls
   `lattice-forge-emit-runtime-profile` to produce a flat `RuntimeProfile`
   document:

   ```sh
   lattice-forge-emit-runtime-profile \
       examples/runtime-asset.gaia-osm-ingest.json \
       --output build/runtime-profiles/gaia-osm-ingest.runtime-profile.json
   ```

   The resulting `RuntimeProfile` contains every field a runner needs without
   requiring it to parse the full `RuntimeAsset`:

   ```json
   {
     "apiVersion": "lattice.socioprophet.dev/v1",
     "kind": "RuntimeProfile",
     "profile": "lattice-forge/gaia-osm-ingest:0.1.0",
     "prophetArtifact": "gaia.bounded-osm-ingest",
     "ownerRepo": "SocioProphet/gaia-world-model",
     "safetyClass": "bounded",
     "runtimeClass": "cli",
     "languages": ["python", "shell"],
     "policy": {
       "network": "restricted",
       "secrets": "none",
       "accelerators": ["cpu"],
       "defaultIsolation": "container"
     },
     "sbomDigest": "sha256:dddd...",
     "signatureDigest": "sha256:eeee...",
     "provenanceBuilderId": "lattice-forge-gaia-builder",
     "promotionChannel": "dev",
     "artifactDigests": {
       "runtime-image": "sha256:aaaa...",
       "runtime-sbom":  "sha256:bbbb...",
       "runtime-lockfile": "sha256:cccc..."
     }
   }
   ```

3. **Validate** — Before launching, the runner verifies that:
   - `safetyClass` is compatible with the target execution environment.
   - `policy.network`, `policy.secrets`, and `policy.defaultIsolation` match
     the environment's admission policy.
   - All `artifactDigests` match the images or layers it has pulled.

4. **Record** — After execution, the runner records the `profile` reference and
   `artifactDigests` into an `EvidenceBundle` and `Factsheet` object so the
   result is traceable back to this exact runtime substrate.

## Label validation

Lattice Forge validates the following optional labels whenever they appear in
`metadata.labels`:

| Label             | Format                                                | Example                          |
|-------------------|-------------------------------------------------------|----------------------------------|
| `prophetArtifact` | lowercase dotted identifier `[a-z][a-z0-9._-]{0,62}` | `gaia.bounded-osm-ingest`        |
| `ownerRepo`       | `<owner>/<repo>` with GitHub-safe characters          | `SocioProphet/gaia-world-model`  |
| `safetyClass`     | one of `bounded`, `critical`, `experimental`, `deprecated` | `bounded`               |

Other labels are passed through unchanged (all values must be non-empty strings).

## Available RuntimeAsset examples

| File                                              | RuntimeClass   | ProphetArtifact              |
|---------------------------------------------------|----------------|------------------------------|
| `examples/runtime-asset.example.json`             | `notebook`     | *(none)*                     |
| `examples/runtime-asset.gaia-osm-ingest.json`     | `cli`          | `gaia.bounded-osm-ingest`    |
| `examples/runtime-asset.notebook-to-artifact.json`| `cli`          | `prophet.notebook-promotion` |
| `examples/runtime-asset.sourceos-image-build.json`| `system-tool`  | `sourceos.image-build`       |

## Evidence bundle fields

A `RuntimeAsset` carries the following evidence that is propagated into the
`EvidenceBundle`:

| Field                  | Purpose                                                  |
|------------------------|----------------------------------------------------------|
| `spec.sbom`            | SPDX/CycloneDX software bill of materials digest         |
| `spec.signature`       | Sigstore/cosign bundle digest for artifact verification  |
| `spec.provenance`      | SLSA/in-toto attestation references and builder ID       |
| `spec.scan`            | Vulnerability, license, and policy scan results          |
| `spec.promotion`       | Channel and rollback reference for safe promotion        |

Runners must record all five evidence categories when creating an
`EvidenceBundle` linked to a `ProphetArtifact` execution.
