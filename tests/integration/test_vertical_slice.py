import pytest

from packages.zt_platform.core import Denied, Platform, Principal, TOOLS


def actor(tenant="acme", subject="alice", roles=("analyst",), scopes=("kb:read", "messages:send")):
    return Principal(subject, tenant, frozenset(roles), frozenset(scopes))


def test_authorized_cited_retrieval_and_tenant_filter():
    app = Platform()
    rows = app.search(actor(), "returns", 5, "corr-rag")
    assert rows and all(row["chunk_id"].startswith("acme-") for row in rows)
    assert all("source" in row for row in rows) and "IGNORE POLICY" not in str(rows)


def test_approval_argument_binding_replay_and_outbox_dlp():
    app = Platform()
    requester = actor()
    approver = actor(subject="bob", roles=("approver",))
    args = {"ticket_id": "ACME-1", "body": "password=synthetic-value"}
    handle = app.approvals.issue(
        requester, approver, TOOLS["send_customer_reply"], args, "corr-approve"
    )
    with pytest.raises(Denied, match="APPROVAL_BINDING_MISMATCH"):
        app.invoke(
            requester, "send_customer_reply", {**args, "body": "changed"}, "corr-approve", handle
        )
    app.invoke(requester, "send_customer_reply", args, "corr-approve", handle, "idem-1")
    assert app.outbox == [
        {
            "tenant": "acme",
            "ticket_id": "ACME-1",
            "body": "[REDACTED]",
            "labels": ["SENSITIVE_DATA"],
        }
    ]
    with pytest.raises(Denied, match="APPROVAL_REPLAY"):
        app.invoke(requester, "send_customer_reply", args, "corr-approve", handle)
    assert app.audit.verify()


def test_cross_tenant_approval_and_unapproved_execution_denied():
    app = Platform()
    requester = actor()
    with pytest.raises(Denied, match="APPROVER_TENANT_MISMATCH"):
        app.approvals.issue(
            requester,
            actor("globex", "bob", ("approver",)),
            TOOLS["send_customer_reply"],
            {"ticket_id": "1", "body": "ok"},
            "c",
        )
    with pytest.raises(Denied, match="APPROVAL_REQUIRED"):
        app.invoke(requester, "send_customer_reply", {"ticket_id": "1", "body": "ok"}, "c")
