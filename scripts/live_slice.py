"""Exercise the real Keycloak -> JWKS -> OPA -> PostgreSQL RLS slice."""

from __future__ import annotations

import json
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

TOKEN_URL = "http://127.0.0.1:8080/realms/support/protocol/openid-connect/token"
API_URL = "http://127.0.0.1:8000/live/knowledge"


def request_json(request: Request, timeout: float = 3.0) -> tuple[int, dict]:
    try:
        with urlopen(request, timeout=timeout) as response:
            return response.status, json.loads(response.read().decode())
    except HTTPError as exc:
        return exc.code, json.loads(exc.read().decode())


def get_alice_token() -> str:
    body = urlencode(
        {
            "grant_type": "password",
            "client_id": "platform-ci",
            "username": "alice-acme",
            "password": "synthetic-alice-password",
            "scope": "openid kb:read",
        }
    ).encode()
    request = Request(
        TOKEN_URL,
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    last_error: Exception | None = None
    last_response: tuple[int, dict] | None = None
    for _ in range(60):
        try:
            status, payload = request_json(request)
            last_response = (status, payload)
            if status == 200 and isinstance(payload.get("access_token"), str):
                return payload["access_token"]
        except (URLError, TimeoutError, ConnectionError, json.JSONDecodeError) as exc:
            last_error = exc
        time.sleep(2)
    if last_response is not None:
        status, payload = last_response
        raise RuntimeError(f"Keycloak token endpoint returned {status}: {payload}")
    raise RuntimeError("Keycloak token endpoint did not become ready") from last_error


def api_get(token: str, tenant: str) -> tuple[int, dict]:
    request = Request(
        f"{API_URL}/{tenant}",
        headers={"Authorization": f"Bearer {token}"},
        method="GET",
    )
    last_error: Exception | None = None
    for _ in range(30):
        try:
            return request_json(request)
        except (URLError, TimeoutError, ConnectionError, json.JSONDecodeError) as exc:
            last_error = exc
            time.sleep(1)
    raise RuntimeError("API did not become ready") from last_error


def main() -> None:
    token = get_alice_token()
    acme_status, acme = api_get(token, "acme")
    if acme_status != 200:
        raise SystemExit(f"acme allow path failed: {acme_status} {acme}")
    documents = acme.get("documents", [])
    if not documents or {row.get("tenant_id") for row in documents} != {"acme"}:
        raise SystemExit(f"RLS isolation failed: {documents}")
    if acme.get("enforcement", {}).get("application_tenant_where_clause") is not False:
        raise SystemExit("live query no longer proves RLS independently of an application WHERE clause")

    globex_status, globex = api_get(token, "globex")
    if globex_status != 403:
        raise SystemExit(f"cross-tenant request was not denied by OPA: {globex_status} {globex}")

    evidence = {
        "principal": "alice-acme",
        "allow": {
            "requested_tenant": "acme",
            "status": acme_status,
            "visible_tenants": sorted({row["tenant_id"] for row in documents}),
            "enforcement": acme["enforcement"],
        },
        "deny": {
            "requested_tenant": "globex",
            "status": globex_status,
            "reason": globex.get("detail"),
        },
    }
    Path("evidence").mkdir(exist_ok=True)
    Path("evidence/live-slice.json").write_text(json.dumps(evidence, indent=2) + "\n")
    print(json.dumps(evidence, sort_keys=True))


if __name__ == "__main__":
    main()
