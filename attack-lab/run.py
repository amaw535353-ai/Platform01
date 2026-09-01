#!/usr/bin/env python3
import json
from pathlib import Path

from packages.zt_platform.core import Denied, Platform, Principal, VulnerablePlatform

token = Principal(
    "mallory",
    "acme",
    frozenset({"analyst"}),
    frozenset({"kb:read", "messages:send"}),
    audience="support-api",
)
cases = []
for profile, app in (("vulnerable", VulnerablePlatform()), ("hardened", Platform())):
    for name, action in (
        (
            "cross_tenant_retrieval",
            lambda a=app: any(
                x["chunk_id"].startswith("globex") for x in a.search(token, "x", 5, "attack-1")
            ),
        ),
        (
            "wrong_audience_side_effect",
            lambda a=app: bool(
                a.invoke(
                    token, "send_customer_reply", {"ticket_id": "1", "body": "harmless"}, "attack-2"
                )
            ),
        ),
    ):
        try:
            success = bool(action())
            reason = "ATTACK_SUCCEEDED" if success else "NO_CROSS_TENANT_RESULT"
        except Denied as exc:
            success = False
            reason = exc.reason
        cases.append(
            {"profile": profile, "category": name, "attack_success": success, "reason": reason}
        )
Path("evidence").mkdir(exist_ok=True)
Path("evidence/attack-report.json").write_text(
    json.dumps({"test_set": "attack-v1", "cases": cases}, indent=2) + "\n"
)
lines = [
    "# Attack comparison",
    "",
    "| Profile | Category | Attack success | Reason |",
    "|---|---|---:|---|",
] + [
    f"| {x['profile']} | {x['category']} | {str(x['attack_success']).lower()} | {x['reason']} |"
    for x in cases
]
Path("evidence/attack-report.md").write_text("\n".join(lines) + "\n")
print(json.dumps(cases))
