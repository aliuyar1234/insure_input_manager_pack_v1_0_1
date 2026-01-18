# Identity Directory adapter (generic REST)

This interface defines how IEIM queries an enterprise Identity Directory service to retrieve **candidate** identities and relationships. The directory **does not** decide final identity; IEIM remains the deterministic scoring authority.

## Auth

Requests use bearer auth:

```text
Authorization: Bearer <token>
```

## Base path

```text
/v1
```

## Endpoint: search candidates

```text
POST /v1/identity/search
Content-Type: application/json
```

Request:

```json
{
  "request_id": "ieim_search_msg_101f1b6d_ea7b_54b4",
  "top_k": 10,
  "allowed_entity_types": ["CUSTOMER", "POLICY", "CLAIM", "CONTACT", "BROKER"],
  "signals": {
    "policy_number": "45-1234567",
    "claim_number": "CLM-2024-00987654",
    "customer_number": "CUST-000778899",
    "email": "max.mustermann@example.com",
    "phone_e164": "+43123456789",
    "person_name": "Max Mustermann",
    "company_name": "Muster GmbH",
    "address": {
      "postal_code": "1010",
      "city": "Wien",
      "street": "Hauptstrasse 1",
      "country": "AT"
    },
    "date_of_birth": "1980-01-01",
    "vehicle_plate": "W123AB",
    "broker_code": "BRK-00077"
  },
  "options": {
    "include_relationships": true
  }
}
```

Response:

```json
{
  "request_id": "ieim_search_msg_101f1b6d_ea7b_54b4",
  "candidates": [
    {
      "entity_type": "CLAIM",
      "entity_id": "CLM-2024-00987654",
      "source_system": "claims_core",
      "attributes": {
        "claim_number": "CLM-2024-00987654",
        "status": "OPEN"
      },
      "relationships": {
        "policy_number": "45-1234567",
        "holder_customer_number": "CUST-000778899"
      },
      "matched_signals": [
        {
          "signal_type": "CLAIM_NUMBER",
          "match_type": "EXACT",
          "input_value_sha256": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
          "record_value_sha256": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
          "notes_redacted": "Claim number matched exactly.",
          "confidence_hint": 1.0
        }
      ]
    }
  ],
  "warnings": [],
  "trace_id": "id_dir_trace_000001"
}
```

Notes:
- The directory returns **candidates** only. IEIM performs deterministic scoring and thresholding.
- `matched_signals` is retrieval evidence. To reduce PII exposure, hashed values are preferred in evidence fields.

## Endpoint: fetch entity by id

```text
GET /v1/entities/{entity_type}/{entity_id}
```

Response:

```json
{
  "entity_type": "POLICY",
  "entity_id": "45-1234567",
  "source_system": "policy_core",
  "attributes": {
    "policy_number": "45-1234567",
    "product_line": "AUTO",
    "status": "ACTIVE"
  },
  "relationships": {
    "holder_customer_number": "CUST-000778899"
  }
}
```

## Error semantics (fail-closed)

Status codes:

```text
401 missing or invalid token
403 token valid but not permitted
422 invalid request
429 rate limited
503 dependency unavailable
```

If the directory is rate limited or unavailable (429 or 503), IEIM must fail closed by producing an identity status that requires human review and emitting audit evidence for the dependency failure.

