# Zero-Trust Agentic RAG/MCP Platform

A portfolio demonstration in which an untrusted model can propose work but deterministic code validates identity, tenant, scope, immutable tool metadata, arguments, policy obligations, approvals, DLP, and audit fields. Only synthetic `acme` and `globex` data is included. **Never expose the vulnerable lab or supply real data/secrets.**

## Architecture and demo identities

The tested offline core models the BFF, explicit orchestrator, knowledge/workflow MCP enforcement points, approval service, local outbox, tenant repository, DLP, and hash-chained audit log. Compose describes private API, PostgreSQL/pgvector, and OPA boundaries. Keycloak and standards-based token exchange remain an explicitly documented integration gap. Demo identities are `alice-acme` (analyst), `bob-acme` (approver), `auditor-acme`, and equivalent fictional Globex identities; no passwords are committed.

## Setup (each step is one copy/paste block)

1. Install pinned Python dependencies (Python 3.12 and `uv`):
   ```sh
   make bootstrap
   ```
2. Start the loopback-only hardened deployment (requires Docker Compose):
   ```sh
   make up && make seed
   ```
3. Verify deterministic controls without a paid model:
   ```sh
   make test && make security-test && make eval
   ```
4. Generate the harmless before/after attack evidence (does not require containers):
   ```sh
   make attack-report
   ```
5. Generate/scan supply-chain evidence when Syft and Trivy are installed:
   ```sh
   make sbom && make scan
   ```
6. Tear down all profiles and local volumes:
   ```sh
   make down
   ```

The vulnerable service is never in the default profile. A deliberate lab start is `docker compose -f deploy/compose/compose.yaml --profile lab-vulnerable up lab-vulnerable`; it demonstrates cross-tenant retrieval, wrong-audience acceptance, and no-approval simulated execution. See [architecture](docs/architecture.md), [threat model](docs/threat-model.md), [traceability](docs/control-traceability.md), [operations](docs/operations-runbook.md), [evidence](evidence/attack-report.md), and [limitations](docs/limitations.md).

