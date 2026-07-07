def test_register_and_login(client):
    register_resp = client.post(
        "/api/v1/auth/register",
        json={"email": "newuser@example.com", "full_name": "New User", "password": "StrongPass123!"},
    )
    assert register_resp.status_code == 201
    assert register_resp.json()["user"]["email"] == "newuser@example.com"
    assert "access_token" in register_resp.cookies
    assert "refresh_token" in register_resp.cookies

    login_resp = client.post(
        "/api/v1/auth/login",
        json={"email": "newuser@example.com", "password": "StrongPass123!"},
    )
    assert login_resp.status_code == 200
    assert login_resp.json()["user"]["email"] == "newuser@example.com"
    assert "access_token" in login_resp.cookies
    assert "refresh_token" in login_resp.cookies
    # Tokens must live only in httpOnly cookies now, never in a JS-readable body.
    assert "access_token" not in login_resp.json()
    assert "refresh_token" not in login_resp.json()


def test_login_invalid_credentials(client):
    client.post(
        "/api/v1/auth/register",
        json={"email": "user2@example.com", "full_name": "User Two", "password": "StrongPass123!"},
    )
    resp = client.post(
        "/api/v1/auth/login",
        json={"email": "user2@example.com", "password": "WrongPassword"},
    )
    assert resp.status_code == 401
    assert resp.json()["code"] == "INVALID_CREDENTIALS"


def test_me_requires_token(client):
    resp = client.get("/api/v1/auth/me")
    assert resp.status_code == 401


def test_me_returns_current_user(client):
    from app.tests.conftest import make_user_and_login

    headers = make_user_and_login(client, "me@example.com", "StrongPass123!")
    resp = client.get("/api/v1/auth/me", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["email"] == "me@example.com"


def test_user_can_update_own_full_name(client):
    from app.tests.conftest import make_user_and_login

    headers = make_user_and_login(client, "selfupdate@example.com", "StrongPass123!")
    resp = client.patch("/api/v1/auth/me", json={"full_name": "New Name"}, headers=headers)
    assert resp.status_code == 200
    assert resp.json()["full_name"] == "New Name"


def test_user_can_change_own_password_and_login_with_new_one(client):
    from app.tests.conftest import make_user_and_login

    headers = make_user_and_login(client, "pwchange@example.com", "StrongPass123!")
    resp = client.patch("/api/v1/auth/me", json={"password": "NewStrongPass456!"}, headers=headers)
    assert resp.status_code == 200

    old_login = client.post(
        "/api/v1/auth/login", json={"email": "pwchange@example.com", "password": "StrongPass123!"}
    )
    assert old_login.status_code == 401

    new_login = client.post(
        "/api/v1/auth/login", json={"email": "pwchange@example.com", "password": "NewStrongPass456!"}
    )
    assert new_login.status_code == 200


def test_profile_update_cannot_change_role(client):
    """ProfileUpdate has no role/is_active fields at all -- sending them must
    be silently ignored (extra fields), not accepted as a privilege escalation
    path via /auth/me."""
    from app.tests.conftest import make_user_and_login

    headers = make_user_and_login(client, "noescalation@example.com", "StrongPass123!")
    resp = client.patch("/api/v1/auth/me", json={"role": "admin", "is_active": False}, headers=headers)
    assert resp.status_code == 200

    me = client.get("/api/v1/auth/me", headers=headers).json()
    assert me["role"] == "viewer"
    assert me["is_active"] is True


def test_account_locks_after_repeated_failed_logins(client):
    client.post(
        "/api/v1/auth/register",
        json={"email": "lockout@example.com", "full_name": "Lockout Test", "password": "StrongPass123!"},
    )

    for _ in range(5):
        resp = client.post(
            "/api/v1/auth/login",
            json={"email": "lockout@example.com", "password": "WrongPassword"},
        )
        assert resp.status_code == 401
        assert resp.json()["code"] == "INVALID_CREDENTIALS"

    # Even the correct password is now blocked until the lockout window expires.
    resp = client.post(
        "/api/v1/auth/login",
        json={"email": "lockout@example.com", "password": "StrongPass123!"},
    )
    assert resp.status_code == 429
    assert resp.json()["code"] == "ACCOUNT_LOCKED"


def test_successful_login_resets_failed_attempt_counter(client):
    client.post(
        "/api/v1/auth/register",
        json={"email": "resetcounter@example.com", "full_name": "Reset Test", "password": "StrongPass123!"},
    )

    for _ in range(4):
        client.post(
            "/api/v1/auth/login",
            json={"email": "resetcounter@example.com", "password": "WrongPassword"},
        )

    good_login = client.post(
        "/api/v1/auth/login",
        json={"email": "resetcounter@example.com", "password": "StrongPass123!"},
    )
    assert good_login.status_code == 200

    # Counter should be cleared, not still sitting at 4 (one more failure
    # shouldn't trip the 5-attempt lockout immediately after a good login).
    resp = client.post(
        "/api/v1/auth/login",
        json={"email": "resetcounter@example.com", "password": "WrongPassword"},
    )
    assert resp.status_code == 401
    assert resp.json()["code"] == "INVALID_CREDENTIALS"
