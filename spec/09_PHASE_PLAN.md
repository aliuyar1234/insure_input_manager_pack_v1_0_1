# Phase plan

This plan is the implementation sequence for IEIM. It is designed for a phase-by-phase delivery with strict quality gates.

The traceability mapping is in `TRACEABILITY.md`.

## P0 - Foundations and SSOT enforcement

**Objective:** Create repository structure, schemas, and pack verification.

Tasks:
- T-001 Create repository layout (spec/, schemas/, configs/, prompts/, interfaces/, scripts/, tests/, runbooks/, tech/, data/samples) (DONE)
- T-002 Implement JSON Schemas as the stable contracts (DONE)
- T-003 Implement pack verification scripts and CI pipeline integration (DONE)
- T-004 Enforce Single Definition Rule and forbidden-token scanning (DONE)

Exit criteria (Gate G-001) (PASSED):
- All schemas validate
- `bash scripts/verify_pack.sh` passes on the pack

## P1 - Ingestion, raw store, normalization

Tasks:
- T-005 Implement M365 Graph ingestion adapter and cursor management (DONE)
- T-006 Implement IMAP adapter (DONE)
- T-007 Implement SMTP gateway ingest endpoint (DONE)
- T-008 Implement raw store append-only writes with SHA-256 hashing (DONE)
- T-009 Implement MIME parsing and normalization to `NormalizedMessage` (DONE)
- T-010 Implement idempotency keys and deduplication (DONE)

Gate G-002 (PASSED):
- End-to-end ingest -> raw store -> normalize on the sample corpus
- Duplicate emails do not create duplicate outputs

## P2 - Attachment processing

Tasks:
- T-011 Store attachments and compute hashes (DONE)
- T-012 AV scan integration and enforcement (DONE)
- T-013 File type detection (DONE)
- T-014 Text extraction for supported formats (DONE)
- T-015 OCR pipeline for scanned documents (DONE)
- T-016 Derived text artifact storage (DONE)

Gate G-003 (PASSED):
- AV blocks infected attachments and fails closed
- OCR outputs are persisted with confidence metrics

## P3 - Identity resolution

Tasks:
- T-017 Candidate retrieval via CRM/Policy/Claims adapters (DONE)
- T-018 Deterministic scoring and Top-K ranking (DONE)
- T-019 Broker/shared mailbox heuristics (DONE)
- T-020 Request-info draft generation for unresolved identity (DONE)

Gate G-004 (PASSED):
- Identity results match gold expectations for the sample corpus
- Ambiguous cases route to review

## P4 - Classification and extraction

Tasks:
- T-021 Rules engine for high precision classification (DONE)
- T-022 Lightweight deterministic model integration (DONE)
- T-023 LLM adapter integration (optional, gated, with cost guardrails and caching) (DONE)
- T-024 Disagreement gate implementation (DONE)
- T-025 Entity extraction and validation (DONE)
- T-026 Optional IBAN extraction under policy (DONE)

Gate G-005 (PASSED):
- Classification and extraction results match gold expectations for the sample corpus
- Invalid outputs fail closed to review

## P5 - Routing engine and case adapter

Tasks:
- T-027 Implement deterministic routing evaluation against the routing table (DONE)
- T-028 Implement routing rules lint and simulation CLI (DONE)
- T-029 Implement case adapter stub and idempotent create/update (including support for request-info and reply drafts as approved artifacts) (DONE)
- T-030 Implement failure handling and review queues (DONE)

Gate G-006 (PASSED):
- Routing decisions match gold expectations
- Case adapter operations are idempotent

## P6 - Audit integrity and observability

Tasks:
- T-031 Implement audit logger and hash chain (DONE)
- T-032 Implement decision_hash computation (DONE)
- T-033 Implement audit verify job and deterministic reprocess command (`ieimctl reprocess`) (DONE)
- T-034 Implement metrics, logs, traces, and dashboards (DONE)

Gate G-007 (PASSED):
- Audit chain verification passes
- Observability signals exist for all stages

## P7 - HITL and governance

Tasks:
- T-035 Implement review UI/API requirements (DONE)
- T-036 Implement correction record storage and audit linkage (DONE)
- T-037 Implement offline promotion workflow for rules/models (DONE)

Gate G-008 (PASSED):
- HITL corrections are fully auditable
- No auto-learning in production

## P8 - Production hardening and rollout

Tasks:
- T-038 Implement deployment automation and runbooks (including RBAC configuration, key management integration, and retention jobs) (DONE)
- T-039 Implement incident toggles (force review, disable LLM) (DONE)
- T-040 Load testing and scaling validation (DONE)

Gate G-009 (PASSED):
- Release checklist in `QUALITY_GATES.md` is satisfied
- All quality gates pass in CI

---

## P9+ - Enterprise-ready system productization (PLANNED)

The phases below extend the SSOT pack + reference implementation into an installable, operable enterprise system.

Detailed plan and required decisions: `spec/13_ENTERPRISE_PHASE_PLAN_P9_PLUS.md`

## P9 - Production runtime packaging foundation (services, config, and persistence)

Tasks:
- T-041 Service entrypoints and process model (DONE)
- T-042 Configuration layering and validation (DONE)
- T-043 Production persistence adapters (interfaces + one chosen implementation) (DONE)
- T-044 Broker interface + one chosen implementation (DONE)
- T-045 Deterministic job orchestration and idempotency (DONE)

Gate G-010 (PASSED):
- Deployable services start in local mode
- Config validation passes for dev and prod configs
- Store + broker contracts are implemented and tested

## P10 - Installable Docker Compose distribution (starter and production profiles)

Tasks:
- T-046 Docker images (DONE)
- T-047 Compose starter profile (DONE)
- T-048 Compose production-hardened profile (DONE)
- T-049 Install and operator docs (DONE)

Gate G-011 (PASSED):
- Compose install works end-to-end on the sample corpus
- Secure defaults (non-root, least exposure) are enforced

## P11 - Kubernetes and Helm distribution (enterprise install path)

Tasks:
- T-050 Helm chart skeleton (DONE)
- T-051 External dependency configuration (DONE)
- T-052 Operational jobs (DONE)
- T-053 Kubernetes install docs (DONE)

Gate G-012 (PASSED):
- Helm chart renders valid manifests and passes hardening checks

## P12 - Enterprise authentication, RBAC hardening, and Review UI (if required)

Tasks:
- T-054 OIDC integration in API (DONE)
- T-055 Review API implementation (DONE)
- T-056 Minimal web UI (conditional) (DONE)

Gate G-013 (PASSED):
- Auth and HITL readiness (RBAC fail-closed, audited corrections)

## P13 - Production integrations (mail ingest and case adapter)

Tasks:
- T-057 Mail ingestion hardening (DONE)
- T-058 Case adapter first-class implementation (DONE)
- T-059 Generic REST identity directory adapter (conditional) (DONE)

Gate G-014 (PASSED):
- Integration readiness (at least one real ingest + one real case adapter)

## P14 - Observability, backups, retention, and operator experience

Tasks:
- T-060 Metrics and dashboards (OPEN)
- T-061 OpenTelemetry tracing (conditional) (OPEN)
- T-062 Backup and restore procedures (OPEN)
- T-063 Retention enforcement in production (OPEN)

Gate G-015 (NOT STARTED):
- Operability gate (monitoring + backup/restore + retention enforceable)

## P15 - Release engineering, SBOM, signing, and upgrade path

Tasks:
- T-064 Versioning and release metadata (OPEN)
- T-065 Container build and publish pipeline (OPEN)
- T-066 SBOM generation and signing (OPEN)
- T-067 Database migrations and upgrade checks (OPEN)

Gate G-016 (NOT STARTED):
- Release readiness (reproducible artifacts + upgrade checks)

## P16 - Performance, scaling, and enterprise acceptance benchmarks

Tasks:
- T-068 Load test profiles and reports (OPEN)
- T-069 Worker scaling guidance (OPEN)

Gate G-017 (NOT STARTED):
- Performance gate (meets agreed throughput/latency targets)
