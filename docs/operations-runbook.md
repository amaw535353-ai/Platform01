# Operations runbook
Use only loopback/private Codespaces ports. Generate `.env` secrets locally, start with `make up`, migrate/seed, run health/tests, and inspect correlated sanitized events. Rotate sessions and broker keys by invalidating all sessions; offboard a tenant by disabling identities, revoking tokens, deleting tenant rows under privileged audited maintenance, then re-indexing. Back up encrypted PostgreSQL volumes and regularly test restore in isolation. Containment: stop workflow MCP, revoke tokens, preserve audit/export hashes, then investigate. `make down` removes demo volumes.

