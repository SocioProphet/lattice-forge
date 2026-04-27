# Complies with Standards — Multi-Domain Geospatial Intelligence

Status: Draft runtime-admission conformance

This runtime packaging repository consumes the SocioProphet multi-domain geospatial standards package.

## Standards consumed

- `SocioProphet/prophet-platform-standards/docs/standards/070-multidomain-geospatial-standards-alignment.md`
- `SocioProphet/prophet-platform-standards/registry/multidomain-geospatial-standards-map.v1.json`
- `SocioProphet/socioprophet-standards-storage/docs/standards/096-multidomain-geospatial-storage-contracts.md`
- `SocioProphet/socioprophet-standards-knowledge/docs/standards/080-multidomain-geospatial-knowledge-context.md`
- `SocioProphet/socioprophet-agent-standards/docs/standards/020-multidomain-geospatial-agent-runtime.md`
- `SocioProphet/socioprophet-agent-standards/schemas/jsonschema/multidomain/geospatial_agent_runtime_profile.v1.schema.json`

## Implementation responsibility

`Lattice Forge` owns runtime packaging and admission only after executable boundaries exist.

It MUST NOT accept speculative runtime assets that lack:

- executable entrypoint
- schema-bound inputs and outputs
- validation command
- sample fixture
- policy bundle reference
- evidence bundle definition
- replay semantics
- standards cross-reference

## Admission lanes

The following multi-domain geospatial runtime lanes are candidates only after standards conformance is proven:

- OSM ingest / route graph / tile export
- STAC / Earth observation ingest
- AIS / LRIT-authorized maritime ingest
- ADS-B air-domain ingest
- SensorThings / field observation ingest
- CCSDS-like telemetry parser
- sensitive geospatial redaction runtime
- multi-domain fusion runtime
- advisory decision-card runtime

## Safety boundary

Lattice Forge may package governed runtimes for authorized analysis, public safety, humanitarian, logistics, infrastructure, environmental, and customer-owned operational workflows. It must not package ungoverned targeting, evasion, sensitive-site exploitation, or unauthorized tracking workflows.

## Promotion gate

A runtime remains blocked until it validates against `socioprophet-agent-standards`, references storage and knowledge standards for all inputs and outputs, and emits evidence/replay artifacts suitable for Agentplane and SocioSphere governance.
