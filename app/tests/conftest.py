import os

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("JWT_SECRET_KEY", "test-secret")
os.environ.setdefault("RATE_LIMIT_STORAGE_URI", "memory://")
# TestClient sends every request from the same fake IP, so real enforcement
# would trip a shared bucket (e.g. /auth/register's 5/hour) after a handful
# of tests regardless of which real client made them. The separate
# account-lockout mechanism (Redis-counter based, stubbed below via
# `_fake_login_lockout_redis`) is unaffected by this and still exercises
# real logic.
os.environ.setdefault("RATE_LIMIT_ENABLED", "false")

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.database import Base, get_db
from app.main import app

TEST_DATABASE_URL = "sqlite:///:memory:"

engine = create_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)


@pytest.fixture(scope="session", autouse=True)
def _create_tables():
    import app.models  # noqa: F401  ensures all models are registered

    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def db_session():
    connection = engine.connect()
    transaction = connection.begin()
    session = TestingSessionLocal(bind=connection)
    try:
        yield session
    finally:
        session.close()
        transaction.rollback()
        connection.close()


@pytest.fixture
def client(db_session):
    from fastapi.testclient import TestClient

    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture(autouse=True)
def _no_celery_dispatch(monkeypatch):
    """Scan creation normally enqueues a Celery task via Redis. Tests don't
    run a broker, so replace the dispatch call with a no-op."""
    from app.services import scan_service

    monkeypatch.setattr(scan_service, "_dispatch_scan_task", lambda scan: None)


class _FakePipeline:
    def __init__(self, store: dict[str, int]):
        self._store = store
        self._incr_keys: list[str] = []

    def incr(self, key: str):
        self._incr_keys.append(key)
        return self

    def expire(self, key: str, seconds: int):
        return self  # TTL semantics aren't needed for the tests that use this

    def execute(self):
        for key in self._incr_keys:
            self._store[key] = self._store.get(key, 0) + 1
        self._incr_keys = []


class _FakeRedis:
    """Minimal stand-in for the login-lockout counter (get/pipeline/delete)
    so account-lockout tests don't need a real Redis server, matching this
    suite's no-external-infra invariant."""

    def __init__(self):
        self._store: dict[str, int] = {}

    def get(self, key: str):
        return self._store.get(key)

    def delete(self, key: str):
        self._store.pop(key, None)

    def pipeline(self):
        return _FakePipeline(self._store)


@pytest.fixture(autouse=True)
def _fake_login_lockout_redis(monkeypatch):
    fake = _FakeRedis()
    monkeypatch.setattr("app.services.auth_service.get_redis_client", lambda: fake)


def make_user_and_login(client, email: str, password: str, role=None, db_session=None):
    """Register a user via the API, optionally promote their role directly in
    the DB (registration always creates a Viewer), then log in and return the
    Authorization header dict.

    Tokens are set as httpOnly cookies on the response rather than returned
    in the JSON body. We pull the access token out of the Set-Cookie jar and
    hand it back as a Bearer header (which `get_current_user` also accepts)
    instead of relying on the TestClient's shared cookie jar -- several
    tests log in as two different users on the same `client` instance, and
    the cookie jar would just hold whichever login happened most recently.
    """
    client.post(
        "/api/v1/auth/register",
        json={"email": email, "full_name": "Test User", "password": password},
    )

    if role is not None and db_session is not None:
        from app.models.user import User

        user = db_session.query(User).filter(User.email == email).one()
        user.role = role
        db_session.commit()

    login_resp = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    token = login_resp.cookies.get("access_token")
    return {"Authorization": f"Bearer {token}"}
