import time

import pytest

from packages.zt_platform.core import AuditChain, Denied, Principal, TOOLS, redact, validate_args, validate_external_url


def principal(**changes):
    values = {
        "subject": "alice",
        "tenant": "acme",
        "roles": frozenset({"analyst"}),
        "scopes": frozenset({"kb:read"}),
    }
    values.update(changes)
    return Principal(**values)


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ({"audience": "support-api"}, "TOKEN_AUDIENCE_INVALID"),
        ({"issuer": "https://evil.invalid"}, "TOKEN_ISSUER_INVALID"),
        ({"expires_at": int(time.time()) - 1}, "TOKEN_EXPIRED"),
        ({"scopes": frozenset()}, "SCOPE_MISSING"),
        ({"scopes": frozenset({"*", "kb:read"})}, "SCOPE_MISSING"),
    ],
)
def test_token_claims_fail_closed(change, reason):
    with pytest.raises(Denied, match=reason):
        principal(**change).validate("kb:read")


def test_dlp_and_url_controls():
    clean, labels = redact("api_key=synthetic-value and 123-45-6789")
    assert "synthetic-value" not in clean and labels == ["SENSITIVE_DATA"]
    for target in (
        "http://allowed.example/x",
        "https://127.0.0.1/x",
        "https://169.254.169.254/latest",
    ):
        with pytest.raises(Denied):
            validate_external_url(target, frozenset({"allowed.example"}))


def test_audit_tamper_detection():
    chain = AuditChain()
    chain.emit("authentication", principal(), "corr-1", "allow", "OK")
    assert chain.verify()
    chain.events[0]["tenant"] = "globex"
    assert not chain.verify()


def test_registry_and_strict_schemas():
    with pytest.raises(TypeError):
        TOOLS["evil"] = TOOLS["get_ticket"]  # type: ignore[index]
    bad = [
        {"query": "x", "top_k": True},
        {"query": "x", "top_k": 1, "extra": "x"},
        {"query": " x", "top_k": 1},
        {"query": "x", "top_k": 6},
    ]
    for args in bad:
        with pytest.raises(Denied, match="SCHEMA_INVALID"):
            validate_args(TOOLS["search_knowledge"], args)


def test_bearer_password_and_secret_redaction():
    value, labels = redact("Bearer abc.def password=hunter2 secret:token 123-45-6789")
    assert "abc.def" not in value and "hunter2" not in value and "token" not in value
    assert labels == ["SENSITIVE_DATA"]
