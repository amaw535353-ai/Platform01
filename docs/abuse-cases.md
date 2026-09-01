# Abuse cases
1. A poisoned Acme chunk requests a tool call: quarantine is advisory telemetry; scopes and approval still deny it.
2. An Acme analyst requests Globex chunks: application tenant filtering and database FORCE RLS deny it.
3. A support-API token reaches MCP: exact audience validation denies it.
4. An approval argument, tenant, correlation, or tool version changes: canonical binding denies it; replay is denied.
5. Metadata points at loopback/link-local/private IP: URL validation denies before network access.
6. A reply contains seeded credentials/PII: deterministic DLP redacts it before local outbox/audit.

