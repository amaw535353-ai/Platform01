# Limitations and residual risk

This is not production-ready, standards-compliant certification evidence, or proof of universal security. Finite synthetic tests only establish the behavior they execute.

## What is now executed

GitHub Actions builds the hardened API container, runs Gitleaks, runs Trivy and produces a CycloneDX SBOM, starts Keycloak, OPA, and PostgreSQL/pgvector, verifies a signed Keycloak access token through JWKS, obtains a live OPA decision, and exercises PostgreSQL FORCE RLS. The live test proves an Acme principal can retrieve only Acme rows and that an Acme request for a Globex resource is denied by policy.

## Remaining identity and protocol gaps

The live Keycloak realm uses a synthetic direct-access-grant client solely for CI. Browser Authorization Code + PKCE, `state`, OIDC `nonce`, server-side session handling, Secure/HttpOnly/SameSite cookies, CSRF controls, logout/revocation, key-rotation failure testing, and production TLS/hostname configuration are not implemented. Standards-based token exchange and short-lived/down-scoped downstream credentials are also not implemented.

The official MCP SDK and Streamable HTTP transport are not yet an enforcement path. Separate knowledge/workflow MCP servers, protected-resource metadata discovery hardening, MCP authorization interoperability, compromised-MCP output handling, and downstream token audience isolation remain future work.

## Remaining data and distributed-system gaps

The deterministic orchestrator, approvals, idempotency map, local outbox, and audit chain remain in-memory and single-process. Thread locks do not provide cross-process correctness. Durable transactional approvals, replay state, outbox delivery, immutable external audit storage, backup/restore, and workload identity remain unimplemented.

PostgreSQL FORCE RLS is live for the synthetic database slice, but production migration lifecycle, connection-pool tenant reset testing, privileged-role operational controls, backup/restore isolation, and broader database authorization testing remain gaps. pgvector is present, but production embedding/ranking behavior is not the subject of the live test.

## Remaining agent and egress gaps

The deterministic attack lab covers prompt-injection quarantine, token claim failures, strict schemas, immutable registry behavior, approval replay/substitution, idempotency collisions, private-target SSRF rejection, DLP, role denial, and audit tamper detection. DNS rebinding, redirect-chain revalidation, rate/concurrency/cost controls, compromised MCP-server responses, tool-output injection, and real network egress enforcement remain incomplete or design-only.

No real external effects, real customer data, persistent model memory, or paid-model dependency is required or enabled.
