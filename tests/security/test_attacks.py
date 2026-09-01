from packages.zt_platform.core import Denied, Platform, Principal, VulnerablePlatform


def test_same_attacks_different_outcomes():
    token = Principal(
        "mallory",
        "acme",
        frozenset({"analyst"}),
        frozenset({"kb:read", "messages:send"}),
        audience="support-api",
    )
    vulnerable = VulnerablePlatform()
    assert any(
        row["chunk_id"].startswith("globex") for row in vulnerable.search(token, "x", 5, "attack")
    )
    assert vulnerable.invoke(
        token, "send_customer_reply", {"ticket_id": "1", "body": "x"}, "attack"
    )
    hardened = Platform()
    for operation in (
        lambda: hardened.search(token, "x", 5, "attack"),
        lambda: hardened.invoke(
            token, "send_customer_reply", {"ticket_id": "1", "body": "x"}, "attack"
        ),
    ):
        try:
            operation()
        except Denied:
            pass
        else:
            raise AssertionError("hardened attack unexpectedly succeeded")
