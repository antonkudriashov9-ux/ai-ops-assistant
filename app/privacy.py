import re

_PATTERNS = (
    (
        re.compile(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----.*?-----END (?:[A-Z]+ )?PRIVATE KEY-----", re.S),
        "[REDACTED PRIVATE KEY]",
    ),
    (re.compile(r"(?i)(\b[a-z][a-z0-9+.-]*://[^\s/:@]+:)[^\s@]+(@)"), r"\1[REDACTED]\2"),
    (re.compile(r"(?i)(\b(?:bearer|basic)\s+)[A-Za-z0-9._~+/=-]+"), r"\1[REDACTED]"),
    (
        re.compile(
            r"(?i)([\"']?\b(?:[a-z0-9]+[_-])*(?:password|passwd|api[_-]?key|token|secret|authorization)[\"']?\s*[:=]\s*)"
            r"(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)"
        ),
        r"\1[REDACTED]",
    ),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{16,}"), "[REDACTED]"),
    (re.compile(r"\b\d{6,}:[A-Za-z0-9_-]{20,}"), "[REDACTED]"),
)


def redact_secrets(text: str) -> str:
    """Best-effort filtering; engineers must still remove sensitive incident data."""
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    return text
