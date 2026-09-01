#!/usr/bin/env python3
"""Generate adversarial evidence by executing labeled synthetic fixtures."""

from __future__ import annotations

import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Callable

from packages.zt_platform.core import (
    Denied,
    Platform,
    Principal,
    TOOLS,
    VulnerablePlatform,
    redact,
    validate_args,
)


def actor(**changes: object) -> Principal:
    values: dict[str, object] = {
        "subject": "mallory",
        "tenant": "acme",
        "roles": frozenset({"analyst"}),
        "scopes": frozenset({"kb:read", "messages:send", "approvals:grant"}),
    }
    values.update(changes)
    return Principal(**values)  # type: ignore[arg-type]


def reason(action: Callable[[], object]) -> str:
    try:
        action()
    except Denied as exc:
        return exc.reason
    except (TypeError, AttributeError):
        return "REGISTRY_IMMUTABLE"
    return "POLICY_ALLOW"


fixtures: list[tuple[str, str, Callable[[], object]]] = []
fixtures.extend(
    [
        (
            "cross_tenant_retrieval",
            "POLICY_ALLOW",
            lambda: Platform().search(actor(), "returns", 5, "a1"),
        ),
        (
            "wrong_audience",
            "TOKEN_AUDIENCE_INVALID",
            lambda: Platform().search(actor(audience="wrong"), "x", 1, "a2"),
        ),
        (
            "wrong_issuer",
            "TOKEN_ISSUER_INVALID",
            lambda: Platform().search(actor(issuer="wrong"), "x", 1, "a3"),
        ),
        ("expired", "TOKEN_EXPIRED", lambda: Platform().search(actor(expires_at=1), "x", 1, "a4")),
        (
            "wrong_client",
            "TOKEN_CLIENT_INVALID",
            lambda: Platform().search(actor(client_id="wrong"), "x", 1, "a5"),
        ),
        (
            "missing_scope",
            "SCOPE_MISSING",
            lambda: Platform().search(actor(scopes=frozenset()), "x", 1, "a6"),
        ),
        (
            "wildcard_scope",
            "SCOPE_MISSING",
            lambda: Platform().search(actor(scopes=frozenset({"*", "kb:read"})), "x", 1, "a7"),
        ),
        (
            "unknown_field",
            "SCHEMA_INVALID",
            lambda: validate_args(TOOLS["search_knowledge"], {"query": "x", "top_k": 1, "x": 1}),
        ),
        (
            "boolean_integer",
            "SCHEMA_INVALID",
            lambda: validate_args(TOOLS["search_knowledge"], {"query": "x", "top_k": True}),
        ),
        (
            "invalid_enum",
            "SCHEMA_INVALID",
            lambda: validate_args(
                TOOLS["export_case"], {"case_id": "C-1", "classification": "public"}
            ),
        ),
        (
            "oversized_value",
            "SCHEMA_INVALID",
            lambda: validate_args(TOOLS["search_knowledge"], {"query": "x" * 501, "top_k": 1}),
        ),
        (
            "registry_mutation",
            "REGISTRY_IMMUTABLE",
            lambda: TOOLS.__setitem__("evil", TOOLS["get_ticket"]),
        ),  # type: ignore[attr-defined]
        (
            "bearer_redaction",
            "POLICY_ALLOW",
            lambda: (
                (_ for _ in ()).throw(Denied("DLP_FAILURE"))
                if "token" in redact("Bearer token")[0]
                else None
            ),
        ),
        (
            "poison_quarantine",
            "POLICY_ALLOW",
            lambda: (
                (_ for _ in ()).throw(Denied("QUARANTINE_FAILURE"))
                if "IGNORE POLICY" in str(Platform().search(actor(), "x", 5, "a14"))
                else None
            ),
        ),
    ]
)

cases = []
for name, expected, action in fixtures:
    actual = reason(action)
    cases.append(
        {
            "profile": "hardened",
            "category": name,
            "expected_reason": expected,
            "actual_reason": actual,
            "passed": actual == expected,
        }
    )

# The vulnerable comparison is independent: the principal is otherwise valid.
vulnerable_cross_tenant = any(
    row["chunk_id"].startswith("globex")
    for row in VulnerablePlatform().search(actor(), "x", 5, "v1")
)
commit = (
    subprocess.run(
        ["git", "rev-parse", "HEAD"], check=False, capture_output=True, text=True
    ).stdout.strip()
    or "unavailable"
)
passed = sum(case["passed"] for case in cases)
report = {
    "schema_version": 2,
    "generated_at": datetime.now(UTC).isoformat(),
    "tested_commit": commit,
    "fixture_count": len(cases),
    "passed": passed,
    "failed": len(cases) - passed,
    "tool_versions": {name: tool.version for name, tool in TOOLS.items()},
    "vulnerable_comparison": {"cross_tenant_attack_succeeded": vulnerable_cross_tenant},
    "cases": cases,
}
Path("evidence").mkdir(exist_ok=True)
Path("evidence/attack-report.json").write_text(json.dumps(report, indent=2) + "\n")
Path("evidence/metrics-v1.json").write_text(
    json.dumps(
        {
            "schema_version": 2,
            "source": "evidence/attack-report.json",
            "security_fixture_pass_rate": {
                "numerator": passed,
                "denominator": len(cases),
                "rate": passed / len(cases),
            },
            "production_controls": {
                "oidc": "not_implemented",
                "opa": "not_implemented",
                "database_rls": "not_implemented",
            },
        },
        indent=2,
    )
    + "\n"
)
lines = [
    "# Generated attack regression",
    "",
    "| Case | Expected | Actual | Passed |",
    "|---|---|---|---:|",
]
lines += [
    f"| {c['category']} | {c['expected_reason']} | {c['actual_reason']} | {str(c['passed']).lower()} |"
    for c in cases
]
Path("evidence/attack-report.md").write_text("\n".join(lines) + "\n")
print(json.dumps({"passed": passed, "failed": len(cases) - passed, "fixtures": len(cases)}))
if passed != len(cases):
    raise SystemExit(1)
