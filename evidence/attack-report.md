# Generated attack regression

| Case | Expected | Actual | Passed |
|---|---|---|---:|
| cross_tenant_retrieval | POLICY_ALLOW | POLICY_ALLOW | true |
| wrong_audience | TOKEN_AUDIENCE_INVALID | TOKEN_AUDIENCE_INVALID | true |
| wrong_issuer | TOKEN_ISSUER_INVALID | TOKEN_ISSUER_INVALID | true |
| expired | TOKEN_EXPIRED | TOKEN_EXPIRED | true |
| wrong_client | TOKEN_CLIENT_INVALID | TOKEN_CLIENT_INVALID | true |
| missing_scope | SCOPE_MISSING | SCOPE_MISSING | true |
| wildcard_scope | SCOPE_MISSING | SCOPE_MISSING | true |
| unknown_field | SCHEMA_INVALID | SCHEMA_INVALID | true |
| boolean_integer | SCHEMA_INVALID | SCHEMA_INVALID | true |
| invalid_enum | SCHEMA_INVALID | SCHEMA_INVALID | true |
| oversized_value | SCHEMA_INVALID | SCHEMA_INVALID | true |
| registry_mutation | REGISTRY_IMMUTABLE | REGISTRY_IMMUTABLE | true |
| bearer_redaction | POLICY_ALLOW | POLICY_ALLOW | true |
| poison_quarantine | POLICY_ALLOW | POLICY_ALLOW | true |
