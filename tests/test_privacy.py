from app.privacy import redact_secrets


def test_credentials_are_removed_without_destroying_diagnostic_context():
    raw = (
        "postgresql://ops:super-secret@db:5432/app connection refused\n"
        "Authorization: Bearer secret-token\npassword=hunter2\n"
        "api_key='sk-abcdefghijklmnopqrstuvwxyz'\n"
        "bot 123456789:abcdefghijklmnopqrstuvwxyz12345"
    )
    clean = redact_secrets(raw)
    for secret in (
        "super-secret",
        "secret-token",
        "hunter2",
        "sk-abcdefghijklmnopqrstuvwxyz",
        "123456789:abcdefghijklmnopqrstuvwxyz12345",
    ):
        assert secret not in clean
    assert "connection refused" in clean
    assert "db:5432/app" in clean


def test_environment_credentials_and_private_keys_are_filtered():
    raw = (
        'OPENAI_API_KEY=private-value\nPOSTGRES_PASSWORD="another-secret"\n'
        "-----BEGIN RSA PRIVATE KEY-----\nprivate-material\n-----END RSA PRIVATE KEY-----"
    )
    clean = redact_secrets(raw)
    for value in ("private-value", "another-secret", "private-material"):
        assert value not in clean
