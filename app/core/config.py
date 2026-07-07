from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    APP_NAME: str = "PentestFlow API"
    APP_ENV: str = "development"
    API_V1_PREFIX: str = "/api/v1"

    DATABASE_URL: str = "postgresql+psycopg://pentestflow:pentestflow@postgres:5432/pentestflow"
    REDIS_URL: str = "redis://redis:6379/0"

    JWT_SECRET_KEY: str = "change-me"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    ACCESS_TOKEN_COOKIE_NAME: str = "access_token"
    REFRESH_TOKEN_COOKIE_NAME: str = "refresh_token"
    # False for local http dev. Set true in any real deployment served over
    # HTTPS -- browsers silently drop `Secure` cookies over plain http.
    COOKIE_SECURE: bool = False
    # "lax" blocks cookies on cross-site POST/PUT/DELETE (our CSRF
    # mitigation, since this is a pure JSON API with no HTML form
    # submissions) while still allowing normal same-site fetch usage.
    COOKIE_SAMESITE: str = "lax"

    CORS_ORIGINS: str = "http://localhost:3000,http://127.0.0.1:3000"

    # In-memory by default -- zero external dependency, fine for a single API
    # process (and required so `pytest` keeps working without Redis, per
    # README's "tests do not require Postgres/Redis/Docker"). Point this at
    # Redis (e.g. redis://redis:6379/1) once running more than one API
    # replica, so rate limits are shared/consistent across processes.
    RATE_LIMIT_STORAGE_URI: str = "memory://"
    # Only false in the test suite (see conftest.py) -- TestClient sends
    # every request from the same fake IP, so real enforcement would trip
    # after a handful of tests regardless of which real client made them.
    RATE_LIMIT_ENABLED: bool = True

    ZAP_DOCKER_IMAGE: str = "ghcr.io/zaproxy/zaproxy:stable"
    SCAN_OUTPUT_DIR: str = "/app/scan_outputs"
    REPORT_OUTPUT_DIR: str = "/app/reports"
    # Name of the Docker named volume backing SCAN_OUTPUT_DIR. The Celery
    # worker talks to the *host* Docker daemon (via the mounted socket) to
    # launch ZAP as a sibling container, so it must bind-mount this shared
    # named volume rather than SCAN_OUTPUT_DIR's in-container path -- that
    # path only exists inside the worker's own container filesystem, not on
    # the host, and the host daemon can't resolve it.
    SCAN_OUTPUT_VOLUME_NAME: str = "pentestflow_scan_outputs"

    ALLOW_LOCALHOST: bool = True
    ALLOW_PRIVATE_IPS: bool = True
    BLOCK_PUBLIC_TARGETS: bool = True
    REQUIRE_SCOPE_CONFIRMATION: bool = True

    @property
    def cors_origins_list(self) -> list[str]:
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
