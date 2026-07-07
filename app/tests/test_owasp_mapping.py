from app.services.owasp_mapper import map_alert_name_to_category


def test_missing_csp_maps_to_a05():
    assert map_alert_name_to_category("Missing Content Security Policy Header") == "A05"


def test_cookie_secure_flag_maps_to_a02():
    assert map_alert_name_to_category("Cookie Missing Secure Flag") == "A02"


def test_outdated_dependency_maps_to_a06():
    assert map_alert_name_to_category("Outdated Dependency Found") == "A06"


def test_missing_rate_limiting_maps_to_a07():
    assert map_alert_name_to_category("Missing Rate Limiting on Login") == "A07"


def test_ssrf_maps_to_a10():
    assert map_alert_name_to_category("Server Side Request Forgery finding") == "A10"


def test_missing_authorization_maps_to_a01():
    assert map_alert_name_to_category("Missing Authorization Check") == "A01"
