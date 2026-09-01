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
    validate_external_url,
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


def tenant_isolation() -> None:
    rows = Platform().search(actor(), "returns", 5, "tenant-isolation")
    if any(row["chunk_id"].startswith("globex") for row in rows):
        raise Denied("TENANT_ISOLATION_FAILURE")


def approver(subject: str = "bob", tenant: str = "acme") -> Principal:
    return actor(
        subject=subject,
        tenant=tenant,
        roles=frozenset({"approver"}),
        scopes=frozenset({"approvals:grant"}),
    )


def approval_replay() -> object:
    platform = Platform()
    requester = actor(subject="alice")
    args = {"ticket_id": "ACME-1", "body": "approved reply"}
    handle = platform.approvals.issue(
        requester,
        approver(),
        TOOLS["send_customer_reply"],
        args,
        "approval-replay",
    )
    platform.invoke(
        requester,
        "send_customer_reply",
        args,
        "approval-replay",
        approval=handle,
        idempotency_key="first-execution",
    )
    return platform.invoke(
        requester,
        "send_customer_reply",
        args,
        "approval-replay",
        approval=handle,
        idempotency_key="replay-execution",
    )


def approval_argument_substitution() -> object:
    platform = Platform()
    requester = actor(subject="alice")
    approved = {"ticket_id": "ACME-1", "body": "approved reply"}
    changed = {"ticket_id": "ACME-1", "body": "attacker changed reply"}
    handle = platform.approvals.issue(
        requester,
        approver(),
        TOOLS["send_customer_reply"],
        approved,
        "approval-substitution",
    )
    return platform.invoke(
        requester,
        "send_customer_reply",
        changed,
        "approval-substitution",
        approval=handle,
        idempotency_key="substitution",
    )


def cross_tenant_approval() -> object:
    requester = actor(subject="alice")
    args = {"ticket_id": "ACME-1", "body": "approved reply"}
    return Platform().approvals.issue(
        requester,
        approver(tenant="globex"),
        TOOLS["send_customer_reply"],
        args,
        "cross-tenant-approval",
    )


def idempotency_collision() -> object:
    platform = Platform()
    requester = actor(scopes=frozenset({"tickets:draft"}))
    platform.invoke(
        requester,
        "create_ticket_draft",
        {"ticket_id": "ACME-1", "body": "first"},
        "idempotency",
        idempotency_key="same-key",
    )
    return platform.invoke(
        requester,
        "create_ticket_draft",
        {"ticket_id": "ACME-1", "body": "changed"},
        "idempotency",
        idempotency_key="same-key",
    )


def dlp_outbox() -> None:
    platform = Platform()
    requester = actor(subject="alice")
    args = {"ticket_id": "ACME-1", "body": "password=supersecret"}
    handle = platform.approvals.issue(
        requester,
        approver(),
        TOOLS["send_customer_reply"],
        args,
        "dlp-outbox",
    )
    platform.invoke(
        requester,
        "send_customer_reply",
        args,
        "dlp-outbox",
        approval=handle,
        idempotency_key="dlp",
    )
    if "supersecret" in platform.outbox[0]["body"]:
        raise Denied("DLP_FAILURE")


def audit_tamper_detection() -> None:
    platform = Platform()
    platform.search(actor(), "returns", 1, "audit-tamper")
    platform.audit.events[0]["reason"] = "TAMPERED"
    if platform.audit.verify():
        raise Denied("AUDIT_TAMPER_UNDETECTED")


fixtures: list[tuple[str, str, Callable[[], object]]] = [
    ("cross_tenant_retrieval_isolation", "POLICY_ALLOW", tenant_isolation),
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
        lambda: Platform().search(
            actor(scopes=frozenset({"*", "kb:read"})), "x", 1, "a7"
        ),
    ),
    (
        "auditor_tool_denial",
        "ROLE_DENIED",
        lambda: Platform().invoke(
            actor(roles=frozenset({"auditor"}), scopes=frozenset({"tickets:read"})),
            "get_ticket",
            {"ticket_id": "ACME-1"},
            "auditor-deny",
        ),
    ),
    (
        "unknown_field",
        "SCHEMA_INVALID",
        lambda: validate_args(
            TOOLS["search_knowledge"], {"query": "x", "top_k": 1, "x": 1}
        ),
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
        lambda: validate_args(
            TOOLS["search_knowledge"], {"query": "x" * 501, "top_k": 1}
        ),
    ),
    (
        "registry_mutation",
        "REGISTRY_IMMUTABLE",
        lambda: TOOLS.__setitem__("evil", TOOLS["get_ticket"]),
    ),  # type: ignore[attr-defined]
    (
        "private_target_ssrf",
        "EGRESS_PRIVATE_ADDRESS",
        lambda: validate_external_url(
            "https://127.0.0.1/internal", frozenset({"127.0.0.1"})
        ),
    ),
    ("approval_replay", "APPROVAL_REPLAY", approval_replay),
    (
        "approval_argument_substitution",
        "APPROVAL_BINDING_MISMATCH",
        approval_argument_substitution,
    ),
    ("cross_tenant_approval", "APPROVER_TENANT_MISMATCH", cross_tenant_approval),
    ("idempotency_collision", "IDEMPOTENCY_KEY_MISMATCH", idempotency_collision),
    ("dlp_outbox", "POLICY_ALLOW", dlp_outbox),
    ("audit_tamper_detection", "POLICY_ALLOW", audit_tamper_detection),
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
            if "IGNORE POLICY" in str(Platform().search(actor(), "x", 5, "a22"))
            else None
        ),
    ),
]

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
    "schema_version": 3,
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
            "schema_version": 3,
            "source": "evidence/attack-report.json",
            "security_fixture_pass_rate": {
                "numerator": passed,
                "denominator": len(cases),
                "rate": passed / len(cases),
            },
            "live_integration_controls": {
                "oidc_jwks": "separate_security_ci_live_slice",
                "opa": "separate_security_ci_live_slice",
                "database_rls": "separate_security_ci_live_slice",
                "mcp_sdk": "not_implemented",
                "token_exchange": "not_implemented",
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
    f"| {c['category']} | {c['expected_reason']} | {c['actual_reason']} | "
    f"{str(c['passed']).lower()} |"
    for c in cases
]
Path("evidence/attack-report.md").write_text("\n".join(lines) + "\n")
print(json.dumps({"passed": passed, "failed": len(cases) - passed, "fixtures": len(cases)}))
if passed != len(cases):
    raise SystemExit(1)
