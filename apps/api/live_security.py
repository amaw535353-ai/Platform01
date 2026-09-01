"""Live zero-trust vertical slice backed by Keycloak, OPA, and PostgreSQL RLS."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

import httpx
import jwt
import psycopg
from fastapi import HTTPException
from jwt import PyJWKClient


@dataclass(frozen=True)
class LiveSettings:
    issuer: str
    jwks_uri: str
    audience: str
    opa_decision_url: str
    database_url: str

    @classmethod
    def from_env(cls) -> "LiveSettings":
        return cls(
            issuer=os.getenv(
                "OIDC_ISSUER", "http://127.0.0.1:8080/realms/support"
            ),
            jwks_uri=os.getenv(
                "OIDC_JWKS_URI",
                "http://keycloak:8080/realms/support/protocol/openid-connect/certs",
            ),
            audience=os.getenv("OIDC_AUDIENCE", "platform-api"),
            opa_decision_url=os.getenv(
                "OPA_DECISION_URL", "http://opa:8181/v1/data/agent/authz/decision"
            ),
            database_url=os.getenv(
                "DATABASE_URL",
                "postgresql://app_login:synthetic-app-password@postgres:5432/platform",
            ),
        )


SETTINGS = LiveSettings.from_env()
JWKS = PyJWKClient(SETTINGS.jwks_uri, cache_jwk_set=True, lifespan=300)


def _unauthorized(reason: str) -> HTTPException:
    return HTTPException(status_code=401, detail=reason, headers={"WWW-Authenticate": "Bearer"})


def verify_access_token(authorization: str | None) -> dict[str, Any]:
    if not authorization or not authorization.startswith("Bearer "):
        raise _unauthorized("BEARER_TOKEN_REQUIRED")
    token = authorization.removeprefix("Bearer ").strip()
    if not token:
        raise _unauthorized("BEARER_TOKEN_REQUIRED")
    try:
        key = JWKS.get_signing_key_from_jwt(token).key
        claims = jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            audience=SETTINGS.audience,
            issuer=SETTINGS.issuer,
            options={"require": ["aud", "exp", "iat", "iss", "sub"]},
        )
    except jwt.PyJWTError as exc:
        raise _unauthorized("TOKEN_INVALID") from exc
    tenant = claims.get("tenant_id")
    if not isinstance(tenant, str) or not tenant.strip():
        raise _unauthorized("TENANT_CLAIM_REQUIRED")
    return claims


def _scopes(claims: dict[str, Any]) -> list[str]:
    value = claims.get("scope", "")
    if not isinstance(value, str):
        return []
    return [scope for scope in value.split() if scope]


def authorize_with_opa(claims: dict[str, Any], resource_tenant: str) -> dict[str, Any]:
    payload = {
        "input": {
            "principal": {
                "subject": claims["sub"],
                "tenant": claims["tenant_id"],
                "scopes": _scopes(claims),
            },
            "resource": {"tenant": resource_tenant},
            "tool": {"name": "search_knowledge", "required_scope": "kb:read", "approval": False},
        }
    }
    try:
        response = httpx.post(SETTINGS.opa_decision_url, json=payload, timeout=2.0)
        response.raise_for_status()
        body = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise HTTPException(status_code=503, detail="OPA_UNAVAILABLE") from exc
    decision = body.get("result")
    if not isinstance(decision, dict):
        raise HTTPException(status_code=503, detail="OPA_DECISION_MISSING")
    if decision.get("allow") is not True:
        reason = decision.get("reason", "POLICY_DEFAULT_DENY")
        raise HTTPException(status_code=403, detail=str(reason))
    return decision


def fetch_rls_documents(principal_tenant: str) -> list[dict[str, str]]:
    """Query without a tenant WHERE clause; PostgreSQL FORCE RLS is the boundary."""
    try:
        with psycopg.connect(SETTINGS.database_url) as connection:
            with connection.cursor() as cursor:
                cursor.execute("SELECT set_config('app.tenant_id', %s, true)", (principal_tenant,))
                cursor.execute("SELECT id, tenant_id, content FROM documents ORDER BY id")
                rows = cursor.fetchall()
    except psycopg.Error as exc:
        raise HTTPException(status_code=503, detail="DATABASE_UNAVAILABLE") from exc
    return [
        {"id": str(row[0]), "tenant_id": str(row[1]), "content": str(row[2])}
        for row in rows
    ]


def live_knowledge(authorization: str | None, resource_tenant: str) -> dict[str, Any]:
    claims = verify_access_token(authorization)
    decision = authorize_with_opa(claims, resource_tenant)
    principal_tenant = str(claims["tenant_id"])
    documents = fetch_rls_documents(principal_tenant)
    return {
        "principal": {"sub": claims["sub"], "tenant": principal_tenant},
        "resource_tenant": resource_tenant,
        "documents": documents,
        "enforcement": {
            "jwt_jwks": "verified",
            "opa": decision.get("reason", "POLICY_ALLOW"),
            "postgres_rls": "forced",
            "application_tenant_where_clause": False,
        },
    }
