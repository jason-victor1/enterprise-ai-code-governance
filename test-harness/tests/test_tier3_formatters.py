from app.tier3_formatters import OutputFormatter


def test_sanitize_audit_log():
    raw = "User logged in\nRole: Admin\r\nSession: valid"
    clean = OutputFormatter.sanitize_audit_log(raw)
    assert "\n" not in clean
    assert "\r" not in clean
    assert clean == "User logged in Role: Admin Session: valid"


def test_mask_sensitive_token():
    token = "ghp_ABC123XYZ789SECRET"
    masked = OutputFormatter.mask_sensitive_token(token, visible_suffix_len=4)
    assert masked.endswith("CRET")
    assert masked.startswith("******************")
    assert len(masked) == len(token)


def test_slugify():
    raw = "Enterprise AI Governance! (v1.0)"
    assert OutputFormatter.slugify(raw) == "enterprise-ai-governance-v10"
