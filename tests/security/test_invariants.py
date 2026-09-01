import threading

import pytest

from packages.zt_platform.core import Denied, Platform, Principal, TOOLS


def actor(
    subject="alice",
    tenant="acme",
    roles=("analyst",),
    scopes=("messages:send", "tickets:write", "approvals:grant"),
    **claims,
):
    values = dict(subject=subject, tenant=tenant, roles=frozenset(roles), scopes=frozenset(scopes))
    values.update(claims)
    return Principal(**values)


def approval(app, args, correlation="c", ttl=300):
    return app.approvals.issue(
        actor(),
        actor("bob", roles=("approver",)),
        TOOLS["send_customer_reply"],
        args,
        correlation,
        ttl,
    )


@pytest.mark.parametrize(
    "claims,reason",
    [
        ({"issuer": "evil"}, "TOKEN_ISSUER_INVALID"),
        ({"audience": "evil"}, "TOKEN_AUDIENCE_INVALID"),
        ({"client_id": "evil"}, "TOKEN_CLIENT_INVALID"),
        ({"expires_at": 1}, "TOKEN_EXPIRED"),
        ({"scopes": ()}, "SCOPE_MISSING"),
        ({"scopes": ("*", "messages:send")}, "SCOPE_MISSING"),
    ],
)
def test_invalid_requester_approval(claims, reason):
    with pytest.raises(Denied, match=reason):
        Platform().approvals.issue(
            actor(**claims),
            actor("bob", roles=("approver",)),
            TOOLS["send_customer_reply"],
            {"ticket_id": "T-1", "body": "x"},
            "c",
        )


def test_invalid_approver_and_separation():
    app = Platform()
    args = {"ticket_id": "T-1", "body": "x"}
    with pytest.raises(Denied, match="APPROVER_TENANT_MISMATCH"):
        app.approvals.issue(
            actor(), actor("bob", "globex", ("approver",)), TOOLS["send_customer_reply"], args, "c"
        )
    with pytest.raises(Denied, match="SELF_APPROVAL_DENIED"):
        app.approvals.issue(
            actor(), actor(roles=("approver",)), TOOLS["send_customer_reply"], args, "c"
        )


def test_expiry_argument_and_correlation_bindings_and_denial_audit():
    app = Platform()
    args = {"ticket_id": "T-1", "body": "x"}
    handle = approval(app, args, ttl=-1)
    with pytest.raises(Denied, match="APPROVAL_EXPIRED"):
        app.invoke(actor(), "send_customer_reply", args, "c", handle, "i")
    handle = approval(app, args)
    with pytest.raises(Denied, match="APPROVAL_BINDING_MISMATCH"):
        app.invoke(actor(), "send_customer_reply", {**args, "body": "y"}, "c", handle, "j")
    assert app.audit.events[-1]["outcome"] == "deny" and app.audit.verify()


def test_atomic_single_use():
    app = Platform()
    args = {"ticket_id": "T-1", "body": "x"}
    handle = approval(app, args)
    barrier = threading.Barrier(3)
    outcomes = []

    def run(key):
        barrier.wait()
        try:
            app.invoke(actor(), "send_customer_reply", args, "c", handle, key)
            outcomes.append("allow")
        except Denied as exc:
            outcomes.append(exc.reason)

    threads = [threading.Thread(target=run, args=(f"i{x}",)) for x in range(2)]
    for thread in threads:
        thread.start()
    barrier.wait()
    for thread in threads:
        thread.join()
    assert outcomes.count("allow") == 1 and outcomes.count("APPROVAL_REPLAY") == 1


def test_idempotency_and_stale_version():
    app = Platform()
    args = {"ticket_id": "T-1", "body": "x"}
    handle = approval(app, args)
    with pytest.raises(Denied, match="IDEMPOTENCY_REQUIRED"):
        app.invoke(actor(), "send_customer_reply", args, "c", handle)
    first = app.invoke(actor(), "send_customer_reply", args, "c", handle, "same")
    assert app.invoke(actor(), "send_customer_reply", args, "c", handle, "same") == first
    with pytest.raises(Denied, match="IDEMPOTENCY_KEY_MISMATCH"):
        app.invoke(actor(), "send_customer_reply", {**args, "body": "changed"}, "c", handle, "same")
    update = {"ticket_id": "ACME-1", "status": "resolved", "version": 2}
    h = app.approvals.issue(
        actor(), actor("bob", roles=("approver",)), TOOLS["update_ticket"], update, "u"
    )
    with pytest.raises(Denied, match="STALE_VERSION"):
        app.invoke(actor(), "update_ticket", update, "u", h, "update")
