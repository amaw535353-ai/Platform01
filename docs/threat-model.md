# Threat model

**Assets:** tenant knowledge, authorization context, approvals, outbox, audit evidence, availability. **Actors:** analysts, approvers, auditors, tenant admins, compromised users, malicious document authors, and network attackers. **Entry points:** OIDC callback, chat/retrieval, MCP HTTP, ingestion, approval handles, and export.

Trust boundaries are shown in the architecture. Assumptions: TLS and Keycloak signing keys are correctly operated; host/container runtime is trusted for this demo; fixtures are synthetic. Threats include prompt/tool-description injection, confused deputy and token passthrough, cross-tenant access, approval replay/tampering, SSRF, data leakage, denial/cost abuse, and audit tampering. Controls default deny, validate claims/scopes, repeat enforcement, force RLS, bind approvals, constrain schemas/context, redact, allowlist egress, rate/budget (design), and hash-chain events.

Mapping: prompt injection corresponds to OWASP Agentic/GenAI prompt-injection and excessive-agency risks; token and per-request decisions implement NIST SP 800-207/207A resource-centric least privilege; audience validation and no token passthrough implement MCP authorization/security guidance; MITRE ATLAS technique identifiers are not asserted because official current data could not be retrieved in this environment. Residual risks and verification gaps are in `limitations.md`.


## In-memory slice
The tested adversary controls arguments, retry keys, malformed claims, and replay timing against synthetic tenants. Trusted code creates handles, nonces, policy versions, and correlations. Raw tokens, approval material, nonces, bodies, and arguments are excluded from audit events. Host/process compromise, multi-process races, durable rollback, real token cryptography, and external-service enforcement are outside the implemented boundary.
