# Architecture

The repository separates **live enforcement**, **implemented in-process controls**, and **target/design-only components** so diagrams do not imply that every box is already deployed.

## Live integration slice

```mermaid
flowchart LR
 U[Synthetic Keycloak user] -->|signed access token| K[Keycloak]
 K -->|JWKS| B[FastAPI resource server]
 B -->|principal + requested tenant| P[OPA PDP]
 B -->|SET LOCAL app.tenant_id| D[(PostgreSQL + pgvector FORCE RLS)]
 B --> R[Tenant-scoped knowledge result]
 P -->|allow / deny| B
 D -->|RLS-filtered rows| B
```

CI exercises `alice-acme` against this path. The API validates the Keycloak signature through JWKS plus issuer, audience, expiry, and tenant claim. OPA then requires principal/resource tenant equality and `kb:read`. On an allowed request, PostgreSQL executes a document query without an application tenant `WHERE` clause after setting `app.tenant_id`; FORCE RLS supplies the independent row boundary. A request by `alice-acme` for Globex is denied by OPA, while the RLS query independently demonstrates that an Acme database session cannot observe Globex rows.

The Keycloak direct-access-grant client exists only to make the synthetic CI integration reproducible. It is **not** the production browser-authentication design.

## Implemented deterministic reference

```mermaid
flowchart LR
 M[Untrusted model proposal] --> O[Explicit orchestrator / PEP]
 O --> C[Immutable capability registry + strict schemas]
 O --> A[Approval binding / replay protection]
 O --> L[DLP + local outbox]
 O --> T[Redacted hash-chained audit]
 O --> Q[In-memory tenant repository]
```

These controls are exercised by unit, integration, security, and attack-regression tests. Locks, approvals, idempotency, outbox state, and audit state are process-local and are not presented as distributed production guarantees.

## Target architecture — not yet enforcement

The intended next architecture adds a browser BFF using Authorization Code + PKCE, server-side sessions, short-lived/down-scoped token exchange, separate knowledge/workflow MCP servers using the official MCP SDK and Streamable HTTP, durable approval/outbox/audit services, and production workload identity. Those components remain design-only until their paths are executed by CI and added to control traceability.

Every live or future service boundary is treated as authenticated and authorized; network location conveys no trust. Raw user access tokens must not be passed through to downstream MCP servers in the target design.
