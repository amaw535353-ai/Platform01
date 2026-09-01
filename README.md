# Zero-Trust Agentic RAG/MCP Platform

A security portfolio reference in which an untrusted model may propose work, while deterministic code and live infrastructure enforce identity, tenant, scope, policy, data isolation, approvals, DLP, and audit controls. Only synthetic `acme` and `globex` data and credentials are included. **Never expose the vulnerable lab or reuse the demo credentials.**

## Implementation status

| Component | Status |
|---|---|
| Deterministic policy core | ✅ Implemented and tested |
| Tenant-filtered in-memory retrieval | ✅ Implemented and tested |
| Approval binding / replay protection | ✅ Implemented and tested |
| DLP / local outbox | ✅ Implemented and tested |
| Attack regression lab | ✅ Implemented and tested |
| Hardened API container | ✅ Executed in CI |
| Gitleaks | ✅ Executed in CI |
| Trivy / CycloneDX SBOM | ✅ Executed in CI |
| Keycloak signed JWT + JWKS verification | ✅ Live Compose slice / CI |
| OPA HTTP authorization decision | ✅ Live Compose slice / CI |
| PostgreSQL + pgvector FORCE RLS | ✅ Live Compose slice / CI |
| Browser OIDC Authorization Code + PKCE/session | 🟡 Design only |
| Official MCP SDK / Streamable HTTP | 🟡 Design only |
| Short-lived/down-scoped token exchange | 🟡 Design only |
| Durable distributed approvals/outbox/audit | 🟡 Design only |
| External production effects | ❌ Intentionally absent |

The live integration slice is deliberately narrow: a synthetic Keycloak user obtains a signed access token, the API verifies that token using JWKS, OPA independently authorizes the requested tenant, and PostgreSQL FORCE RLS independently limits visible rows. The database query used by the live route contains **no tenant `WHERE` clause**, so the CI evidence demonstrates that row isolation is supplied by PostgreSQL rather than an application filter.

The larger orchestrator, approval, DLP, immutable capability registry, local outbox, and hash-chained audit controls remain an in-process deterministic reference. MCP transport and standards-based token exchange are still target architecture, not claimed enforcement paths.

## Demo identities

Synthetic identities include `alice-acme`, `bob-acme`, `auditor-acme`, and equivalent fictional Globex identities in the deterministic core. The live Keycloak CI realm currently provisions `alice-acme` and `gina-globex`; its committed passwords and bootstrap credentials are intentionally synthetic and local/CI-only.

## Setup

1. Install exactly the locked Python dependencies (Python 3.12 and `uv` 0.12.8):
   ```sh
   make bootstrap
   ```
2. Start the loopback-only live stack (API + Keycloak + OPA + PostgreSQL/pgvector):
   ```sh
   make up
   ```
3. Exercise the live Acme allow / Globex deny slice:
   ```sh
   make live-test
   ```
4. Verify deterministic controls without a paid model:
   ```sh
   make test && make security-test && make eval
   ```
5. Generate the harmless before/after attack evidence:
   ```sh
   make attack-report
   ```
6. Generate/scan supply-chain evidence when Syft and Trivy are installed locally:
   ```sh
   make sbom && make scan
   ```
7. Tear down all profiles and local volumes:
   ```sh
   make down
   ```

The vulnerable service is never in the default profile. A deliberate lab start is `docker compose -f deploy/compose/compose.yaml --profile lab-vulnerable up lab-vulnerable`; it demonstrates intentionally unsafe behavior with synthetic data only.

See [architecture](docs/architecture.md), [threat model](docs/threat-model.md), [control traceability](docs/control-traceability.md), [operations](docs/operations-runbook.md), [attack evidence](evidence/attack-report.md), and [limitations](docs/limitations.md).

## Trust boundary

This repository is a security reference and portfolio demonstration, not a production-ready MCP platform or certification. The live slice proves a real identity → policy → database boundary for tenant-scoped knowledge retrieval. The deterministic core proves additional application-security controls in one Python process. Browser authentication, production session handling, official MCP transport, token exchange, durable multi-process state, workload identity, Kubernetes enforcement, and real external effects remain explicitly out of scope until implemented and tested.
