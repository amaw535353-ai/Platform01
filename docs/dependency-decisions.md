# Dependency decisions (ADR-001)

Recorded 2026-09-01. Runtime pins are in `pyproject.toml`; images use tags and digests in Compose. FastAPI/Pydantic provide HTTP and strict typed boundary schemas, SQLAlchemy is reserved for the PostgreSQL adapter, pytest/Ruff/mypy/Bandit are verification tools. The deterministic offline core deliberately uses the standard library so CI has no model or external-service dependency.

Requested MCP revision `2026-07-28` and a stable official Python SDK v2 could not be verified: the browsing service returned HTTP 401, and therefore the SDK is **not pinned or represented as integrated**. Official URLs to re-check are <https://modelcontextprotocol.io/specification/2026-07-28>, <https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization>, and <https://github.com/modelcontextprotocol/python-sdk>. Keycloak token exchange, LangGraph, Presidio, and an MCP SDK are excluded until compatible current versions and actual integration tests can be verified. Deterministic DLP and orchestration implement the bounded slice without pretending framework conformance.

