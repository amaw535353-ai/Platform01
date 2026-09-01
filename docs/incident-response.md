# Incident response
1. Triage denial spikes, audience failures, cross-tenant attempts, unusual tool sequences, approval replay, injection labels, DLP events, and budget anomalies.
2. Contain by disabling the narrow tool/client/tenant, revoking sessions, and stopping outbox workers.
3. Preserve sanitized audit JSON, configuration versions, and SHA-256 manifests; never export prompts or credentials.
4. Eradicate, rotate, restore, validate tenant boundaries, and obtain approval before resuming.
5. Notify per applicable policy and document timeline/root cause. The mutable hash chain detects modification but is not immutable storage.

