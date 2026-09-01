# Security policy

Do not use real data or credentials. Report issues privately to repository maintainers.

The `lab-vulnerable` profile is intentionally unsafe, loopback-only, synthetic, and must never be exposed or used with hardened data. The Keycloak and PostgreSQL credentials committed under `deploy/` and `db/` are also synthetic local/CI-only credentials; never reuse them outside this demonstration.

The live slice verifies signed Keycloak JWTs through JWKS, calls OPA over HTTP, and exercises PostgreSQL FORCE RLS. It is still bounded demonstration evidence, not a certification or a production identity deployment.
