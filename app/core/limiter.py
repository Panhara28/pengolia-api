from typing import Callable, TypeVar

from fastapi import Request
from fastapi.responses import JSONResponse
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from app.core.config import settings

# In-memory by default (see RATE_LIMIT_STORAGE_URI); point at Redis for
# multi-process deployments so limits are shared/consistent across them.
limiter = Limiter(key_func=get_remote_address, storage_uri=settings.RATE_LIMIT_STORAGE_URI)

F = TypeVar("F", bound=Callable)


def rate_limit(limit_value: str) -> Callable[[F], F]:
    """`@limiter.limit(...)`, but a no-op when RATE_LIMIT_ENABLED is false.

    Only the test suite disables it: TestClient sends every request from
    the same fake IP, so real enforcement would trip a shared bucket after
    a handful of tests regardless of which real client made them. Toggling
    `limiter.enabled` directly doesn't reliably bypass slowapi's decorator
    path, so this wraps at the settings level instead.
    """
    if not settings.RATE_LIMIT_ENABLED:
        return lambda func: func
    return limiter.limit(limit_value)


async def rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
    return JSONResponse(
        status_code=429,
        content={
            "detail": "Too many requests. Please try again later.",
            "code": "RATE_LIMITED",
            "field": None,
        },
    )
