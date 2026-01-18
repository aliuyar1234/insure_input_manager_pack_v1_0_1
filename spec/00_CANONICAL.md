# IEIM — Single Source of Truth (SSOT)

**File:** `spec/00_CANONICAL.md`  
**Canonical version (SemVer):** `1.0.1`

This file is the **only** authoritative location for:
- Canonical IDs and enums (labels, queues, SLAs, stages, module IDs)
- Schema `$id` values (URNs)
- Canonical CLI literals and repository paths
- Canonical exit codes

## Single Definition Rule

- Canonical enums and identifiers are defined **only** in this file.
- All other files may **use** these values, but must not re-define them as authoritative lists.
- This pack enforces the rule via `scripts/check_single_definition_rule.py`.

## 1) Global identifiers

- SYSTEM_ID: `IEIM`
- PACK_ID: `insure_input_manager_pack_v1_0_1`
- CANONICAL_SPEC_SEMVER: `1.0.1`
- HASH_ALGO_PRIMARY: `SHA-256`
- JSON_CANONICALIZATION: `RFC8785` (JSON Canonicalization Scheme)

## 2) Canonical ID strategy

- message_id: UUID (recommended UUIDv7, stored as canonical string)
- attachment_id: UUID (recommended UUIDv7, stored as canonical string)
- audit_event_id: UUID (recommended UUIDv7, stored as canonical string)
- run_id: UUID (recommended UUIDv7, stored as canonical string)
- rule_version: SemVer string
- model_version: provider-specific immutable string
- prompt_version: SemVer string
- prompt_sha256: SHA-256 hex string

## 3) Canonical pipeline stages (AuditEvent.stage)

- STAGE_INGEST: `INGEST`
- STAGE_NORMALIZE: `NORMALIZE`
- STAGE_ATTACHMENTS: `ATTACHMENTS`
- STAGE_IDENTITY: `IDENTITY`
- STAGE_CLASSIFY: `CLASSIFY`
- STAGE_EXTRACT: `EXTRACT`
- STAGE_ROUTE: `ROUTE`
- STAGE_CASE: `CASE`
- STAGE_HITL: `HITL`
- STAGE_REPROCESS: `REPROCESS`

## 4) Schema IDs (JSON Schema `$id` URNs)

- SCHEMA_ID_NORMALIZED_MESSAGE: "urn:ieim:schema:normalized-message:1.0.0"
- SCHEMA_ID_ATTACHMENT_ARTIFACT: "urn:ieim:schema:attachment-artifact:1.0.0"
- SCHEMA_ID_IDENTITY_RESULT: "urn:ieim:schema:identity-resolution-result:1.0.0"
- SCHEMA_ID_CLASSIFICATION_RESULT: "urn:ieim:schema:classification-result:1.0.0"
- SCHEMA_ID_EXTRACTION_RESULT: "urn:ieim:schema:extraction-result:1.0.0"
- SCHEMA_ID_ROUTING_DECISION: "urn:ieim:schema:routing-decision:1.0.0"
- SCHEMA_ID_AUDIT_EVENT: "urn:ieim:schema:audit-event:1.0.0"
- SCHEMA_ID_CORRECTION_RECORD: "urn:ieim:schema:correction-record:1.0.0"

## 5) Canonical enums and label sets

### 5.1 Ingestion sources (NormalizedMessage.ingestion_source)

- INGESTION_SOURCE_M365_GRAPH: `M365_GRAPH`
- INGESTION_SOURCE_IMAP: `IMAP`
- INGESTION_SOURCE_SMTP_GATEWAY: `SMTP_GATEWAY`

### 5.2 Attachment AV statuses (AttachmentArtifact.av_status)

- AV_STATUS_CLEAN: `CLEAN`
- AV_STATUS_INFECTED: `INFECTED`
- AV_STATUS_SUSPICIOUS: `SUSPICIOUS`
- AV_STATUS_FAILED: `FAILED`

### 5.3 Audit actor types (AuditEvent.actor_type)

- ACTOR_TYPE_SYSTEM: `SYSTEM`
- ACTOR_TYPE_HUMAN: `HUMAN`
- ACTOR_TYPE_JOB: `JOB`

### 5.4 Identity target entity types (IdentityResolutionResult.top_k[].entity_type)

- ID_ENTITY_CUSTOMER: `CUSTOMER`
- ID_ENTITY_POLICY: `POLICY`
- ID_ENTITY_CLAIM: `CLAIM`
- ID_ENTITY_CONTACT: `CONTACT`
- ID_ENTITY_BROKER: `BROKER`

### 5.5 Identity status (IdentityResolutionResult.status)

- IDENTITY_CONFIRMED
- IDENTITY_PROBABLE
- IDENTITY_NEEDS_REVIEW
- IDENTITY_NO_CANDIDATE

### 5.6 Intent labels (ClassificationResult.intents[].label, multi-label)

Intent labels are multi-label. A single email may contain multiple intents.

- INTENT_CLAIM_NEW — New claim / first report of loss.
- INTENT_CLAIM_UPDATE — Update to an existing claim.
- INTENT_POLICY_CHANGE — Change request for a policy.
- INTENT_POLICY_CANCELLATION — Cancellation/termination/withdrawal.
- INTENT_BILLING_QUESTION — Billing, payment, dunning, refund.
- INTENT_COMPLAINT — Complaint about service/decision/delay.
- INTENT_LEGAL — Legal correspondence and formal notices.
- INTENT_GDPR_REQUEST — Data subject request (access, deletion, objection).
- INTENT_DOCUMENT_SUBMISSION — Submitting documents (invoice, photos, reports).
- INTENT_COVERAGE_QUESTION — Coverage/terms/exclusions question.
- INTENT_BROKER_INTERMEDIARY — Broker acting on behalf of an insured.
- INTENT_TECHNICAL — Technical issue (portal/login/upload/bounce loops).
- INTENT_GENERAL_INQUIRY — General inquiry; insufficient classification.

### 5.7 Product line labels (ClassificationResult.product_line.label)

- PROD_AUTO — Motor/auto.
- PROD_HOME — Household/home contents.
- PROD_PROPERTY — Building/property.
- PROD_LIABILITY — Private liability.
- PROD_LEGAL_EXPENSE — Legal expenses protection.
- PROD_TRAVEL — Travel.
- PROD_HEALTH — Health/supplementary.
- PROD_LIFE — Life.
- PROD_ACCIDENT — Accident.
- PROD_COMMERCIAL — Commercial/business.
- PROD_UNKNOWN — Cannot be determined safely.

### 5.8 Urgency labels (ClassificationResult.urgency.label)

- URG_CRITICAL — Target first response: 1 hour.
- URG_HIGH — Target first response: 4 hours.
- URG_NORMAL — Target first response: 1 business day.
- URG_LOW — Target first response: 3 business days.

### 5.9 SLA IDs (RoutingDecision.sla_id)

- SLA_1H
- SLA_4H
- SLA_1BD
- SLA_3BD

### 5.10 Risk flags (ClassificationResult.risk_flags[].label, multi-label)

- RISK_LEGAL_THREAT — Legal threat language or lawyer correspondence.
- RISK_REGULATORY — Regulator/ombudsman escalation.
- RISK_FRAUD_SIGNAL — Fraud indicators.
- RISK_VIP — VIP marker from CRM.
- RISK_MEDIA_THREAT — Threat to contact media/social channels.
- RISK_SECURITY_MALWARE — Attachment blocked by AV.
- RISK_PRIVACY_SENSITIVE — Sensitive PII present (bank data, ID docs).
- RISK_SELF_HARM_THREAT — Harm threats detected.
- RISK_LANGUAGE_UNSUPPORTED — Unsupported language detected.
- RISK_AUTOREPLY_LOOP — Auto-reply/bounce loop detected.

### 5.11 Document types (AttachmentArtifact.doc_type_candidates[].doc_type_label)

- DOC_INVOICE
- DOC_POLICE_REPORT
- DOC_MEDICAL_REPORT
- DOC_PHOTO_EVIDENCE
- DOC_CLAIM_FORM
- DOC_POLICY_DOCUMENT
- DOC_ID_DOCUMENT
- DOC_BANK_DETAILS
- DOC_OTHER
- DOC_UNKNOWN

### 5.12 Entity types for extraction (ExtractionResult.entities[].entity_type)

- ENT_POLICY_NUMBER
- ENT_CLAIM_NUMBER
- ENT_CUSTOMER_NUMBER
- ENT_DATE
- ENT_LOCATION
- ENT_VEHICLE_PLATE
- ENT_IBAN
- ENT_EMAIL
- ENT_PHONE
- ENT_ADDRESS
- ENT_PERSON_NAME
- ENT_COMPANY_NAME
- ENT_DOCUMENT_TYPE

### 5.13 Canonical queues (RoutingDecision.queue_id)

- QUEUE_INTAKE_REVIEW_GENERAL
- QUEUE_IDENTITY_REVIEW
- QUEUE_CLASSIFICATION_REVIEW
- QUEUE_SECURITY_REVIEW
- QUEUE_PRIVACY_DSR
- QUEUE_COMPLAINTS
- QUEUE_LEGAL
- QUEUE_FRAUD
- QUEUE_TECH_SUPPORT
- QUEUE_BROKER_SUPPORT
- QUEUE_CLAIMS_AUTO
- QUEUE_CLAIMS_PROPERTY
- QUEUE_CLAIMS_LIABILITY
- QUEUE_POLICY_SERVICE
- QUEUE_BILLING
- QUEUE_UNKNOWN_PRODUCT_REVIEW
- QUEUE_INGESTION_FAILURE_REVIEW
- QUEUE_CASE_CREATE_FAILURE_REVIEW

### 5.14 Routing actions (RoutingDecision.actions[])

- ACTION_CREATE_CASE: `CREATE_CASE`
- ACTION_ATTACH_ORIGINAL_EMAIL: `ATTACH_ORIGINAL_EMAIL`
- ACTION_ATTACH_ALL_FILES: `ATTACH_ALL_FILES`
- ACTION_BLOCK_CASE_CREATE: `BLOCK_CASE_CREATE`
- ACTION_ADD_REQUEST_INFO_DRAFT: `ADD_REQUEST_INFO_DRAFT`
- ACTION_ADD_REPLY_DRAFT: `ADD_REPLY_DRAFT`

### 5.15 Module IDs (traceability)

- MOD_INGEST
- MOD_RAW_STORE
- MOD_NORMALIZE
- MOD_ATTACHMENT
- MOD_IDENTITY
- MOD_CLASSIFY
- MOD_EXTRACT
- MOD_ROUTE
- MOD_CASE_ADAPTER
- MOD_HITL_UI
- MOD_AUDIT
- MOD_OBSERVABILITY
- MOD_SECURITY
- MOD_RULES_REGISTRY

## 6) Multi-label rules and priority logic

### 6.1 Primary intent selection priority (deterministic)

Order (highest first):
1. INTENT_GDPR_REQUEST
2. INTENT_LEGAL
3. INTENT_COMPLAINT
4. INTENT_CLAIM_NEW
5. INTENT_CLAIM_UPDATE
6. INTENT_POLICY_CANCELLATION
7. INTENT_POLICY_CHANGE
8. INTENT_BILLING_QUESTION
9. INTENT_DOCUMENT_SUBMISSION
10. INTENT_COVERAGE_QUESTION
11. INTENT_BROKER_INTERMEDIARY
12. INTENT_TECHNICAL
13. INTENT_GENERAL_INQUIRY

### 6.2 Risk overrides (routing hard overrides)

These overrides are evaluated before all other routing rules:
- RISK_SECURITY_MALWARE => QUEUE_SECURITY_REVIEW, SLA_1H, actions include BLOCK_CASE_CREATE.
- RISK_REGULATORY => QUEUE_COMPLAINTS, SLA_1H.
- RISK_LEGAL_THREAT => QUEUE_LEGAL, SLA_1H.
- RISK_FRAUD_SIGNAL => QUEUE_FRAUD, SLA_4H.
- RISK_LANGUAGE_UNSUPPORTED => QUEUE_INTAKE_REVIEW_GENERAL, SLA_1BD.
- RISK_SELF_HARM_THREAT => QUEUE_INTAKE_REVIEW_GENERAL, SLA_1H, requires human escalation note.

### 6.3 Product line unknown

If product line is PROD_UNKNOWN and intent implies claims or policy service, route to QUEUE_UNKNOWN_PRODUCT_REVIEW unless authoritative lookup (policy/claim) determines product.

## 7) Canonical CLI literals

- CLI_BIN: `ieimctl`
- CLI_COMMANDS:
  - `ieimctl pack verify`
  - `ieimctl ingest simulate`
  - `ieimctl case simulate`
  - `ieimctl rules lint`
  - `ieimctl rules simulate`
  - `ieimctl audit verify`
  - `ieimctl reprocess`
  - `ieimctl hitl list`
  - `ieimctl hitl submit-correction`
  - `ieimctl retention run`
  - `ieimctl loadtest run`

## 8) Canonical repository paths

- PATH_CANONICAL: `spec/00_CANONICAL.md`
- PATH_SCHEMAS_DIR: `schemas/`
- PATH_CONFIG_DEV: `configs/dev.yaml`
- PATH_CONFIG_PROD: `configs/prod.yaml`
- PATH_ROUTING_TABLE_DEFAULT: `configs/routing_tables/routing_rules_v1.4.1.json`

## 9) Canonical exit codes (scripts/CLI)

- EXIT_OK: 0
- EXIT_INVALID_INPUT: 10
- EXIT_SCHEMA_VALIDATION_FAILED: 20
- EXIT_FAIL_CLOSED_REVIEW_REQUIRED: 30
- EXIT_DEPENDENCY_UNAVAILABLE: 40
- EXIT_SECURITY_POLICY_VIOLATION: 50
- EXIT_PACK_VERIFICATION_FAILED: 60
