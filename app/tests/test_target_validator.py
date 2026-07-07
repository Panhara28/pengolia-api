from app.services.target_validator import validate_target_url


def test_localhost_allowed():
    result = validate_target_url("http://localhost:3000")
    assert result.allowed is True


def test_loopback_ip_allowed():
    result = validate_target_url("http://127.0.0.1:8000")
    assert result.allowed is True


def test_private_ip_allowed():
    result = validate_target_url("http://192.168.1.20")
    assert result.allowed is True


def test_unapproved_internal_domain_blocked_by_default():
    result = validate_target_url("https://staging.example.internal")
    assert result.allowed is False


def test_approved_staging_domain_allowed(db_session):
    from app.models.setting import Setting

    db_session.add(
        Setting(
            key="security_scope",
            value_json={"approved_domains": ["staging.example.internal"]},
        )
    )
    db_session.commit()

    result = validate_target_url("https://staging.example.internal", db=db_session)
    assert result.allowed is True


def test_public_domain_blocked_by_default():
    result = validate_target_url("https://google.com")
    assert result.allowed is False


def test_unsupported_protocol_blocked():
    result = validate_target_url("ftp://localhost")
    assert result.allowed is False


def test_javascript_scheme_blocked():
    result = validate_target_url("javascript:alert(1)")
    assert result.allowed is False


def test_empty_url_blocked():
    result = validate_target_url("")
    assert result.allowed is False
