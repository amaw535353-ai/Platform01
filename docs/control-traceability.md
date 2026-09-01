# Control traceability

| Control | Automated evidence | Status |
|---|---|---|
| Signed Keycloak JWT / JWKS, issuer, audience, expiry, tenant claim | `scripts/live_slice.py` in `security-ci` | ✅ Live Compose / CI |
| OPA tenant + scope authorization | `scripts/live_slice.py`, `policies/opa/agent.rego` | ✅ Live HTTP decision / CI |
| PostgreSQL FORCE RLS independent of application tenant filter | `scripts/live_slice.py`, `db/migrations/001_rls.sql` | ✅ Live PostgreSQL / CI |
| Acme allow / Globex cross-tenant deny | `scripts/live_slice.py`, `evidence/live-slice.json` artifact | ✅ Live integration evidence |
| Tenant-filtered in-memory retrieval / quarantine | `tests/integration/test_vertical_slice.py`, attack lab | ✅ Implemented / tested |
| Claim/audience/scope checks in deterministic core | `tests/unit/test_security_core.py`, attack lab | ✅ Implemented / tested |
| Approval binding, expiry, replay and substitution | integration tests + attack lab | ✅ Implemented / tested in-process |
| Idempotency binding | integration tests + attack lab | ✅ Implemented / tested in-process |
| DLP local outbox | integration tests + attack lab | ✅ Implemented / tested in-process |
| Strict capability schemas / immutable registry | unit/schema tests + attack lab | ✅ Implemented / tested |
| SSRF syntax/private target rejection | unit tests + attack lab | ✅ Implemented / no network call |
| Audit hash-chain tamper detection | unit tests + attack lab | ✅ Implemented / mutable local storage |
| Vulnerable vs hardened comparison | `attack-lab/run.py` | ✅ Synthetic regression evidence |
| Hardened container build | `security-ci` | ✅ Executed in CI |
| Gitleaks secret scan | `security-ci` | ✅ Executed in CI |
| Trivy filesystem scan + CycloneDX SBOM | `security-ci` | ✅ Executed in CI |
| Browser Auth Code + PKCE/session controls | none | 🟡 Design only |
| Official MCP SDK / Streamable HTTP | none | 🟡 Design only |
| Short-lived/down-scoped token exchange | none | 🟡 Design only |
| Durable distributed approvals/outbox/audit | none | 🟡 Design only |

The live integration proves the identity, policy, and database boundaries for one tenant-scoped knowledge path. It does not imply that the target MCP or browser-authentication architecture has been implemented.
