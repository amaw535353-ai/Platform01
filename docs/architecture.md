# Architecture

```mermaid
flowchart LR
 U[Browser] -->|OIDC code + PKCE| B[BFF/API]
 B -->|verified principal| O[Explicit orchestrator PEP]
 O -->|down-scoped token| K[Knowledge MCP PEP]
 O -->|down-scoped token| W[Workflow MCP PEP]
 O --> P[OPA PDP]
 K --> P
 W --> P
 K --> D[(PostgreSQL + pgvector RLS)]
 W --> D
 O --> A[Approval service]
 W --> X[(local outbox)]
 B & O & K & W & A --> T[redaction / audit / OTEL]
 I[Keycloak] --> B
```

Every arrow crosses an authenticated, authorized trust boundary; internal location conveys no trust. The API token terminates at the BFF. A broker must exchange it for short-lived `aud=mcp-server` credentials; it may not pass the original token. Trusted code, not LangGraph/FakeLLM, constructs policy facts and dispatches immutable metadata. Retrieval filters tenant/ACL before ranking and again afterward; PostgreSQL FORCE RLS supplies a second boundary. Replies only enter a local outbox.

OAuth browser design requires exact pre-registered redirect URIs, Authorization Code plus PKCE S256, random single-use `state`, OIDC `nonce`, server-side sessions, Secure/HttpOnly/SameSite cookies, CSRF tokens, CSP, and frame denial. MCP publishes protected-resource metadata. Production metadata discovery requires HTTPS and pinned allowlisted hosts with each redirect revalidated.

