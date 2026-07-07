import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.exceptions import (
    ConflictError,
    InvalidCredentialsError,
    TooManyAttemptsError,
    UnauthorizedError,
)
from app.core.redis_client import get_redis_client
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    verify_password,
)
from app.models.user import User, UserRole

# Per-account lockout, independent of source IP -- complements the
# per-IP rate limit on the /auth/login route itself (slowapi), so a
# distributed credential-stuffing attempt against one account is still
# blocked even when spread across many IPs.
MAX_FAILED_LOGIN_ATTEMPTS = 5
LOGIN_LOCKOUT_WINDOW_SECONDS = 15 * 60


def _login_fail_key(email: str) -> str:
    return f"login_fail:{email.strip().lower()}"


def register_user(db: Session, email: str, full_name: str, password: str) -> User:
    existing = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
    if existing:
        raise ConflictError("A user with this email already exists", code="EMAIL_TAKEN")

    user = User(
        email=email,
        full_name=full_name,
        hashed_password=hash_password(password),
        role=UserRole.VIEWER,
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def authenticate_user(db: Session, email: str, password: str) -> User:
    redis_client = get_redis_client()
    fail_key = _login_fail_key(email)

    if int(redis_client.get(fail_key) or 0) >= MAX_FAILED_LOGIN_ATTEMPTS:
        raise TooManyAttemptsError()

    user = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
    if not user or not verify_password(password, user.hashed_password):
        pipe = redis_client.pipeline()
        pipe.incr(fail_key)
        pipe.expire(fail_key, LOGIN_LOCKOUT_WINDOW_SECONDS)
        pipe.execute()
        raise InvalidCredentialsError()

    if not user.is_active:
        raise InvalidCredentialsError("This account has been deactivated")

    redis_client.delete(fail_key)
    return user


def issue_tokens(user: User) -> tuple[str, str]:
    access_token = create_access_token(user.id, user.role.value)
    refresh_token = create_refresh_token(user.id)
    return access_token, refresh_token


def refresh_access_token(db: Session, refresh_token: str) -> tuple[str, str]:
    try:
        payload = decode_token(refresh_token)
    except ValueError as exc:
        raise UnauthorizedError("Invalid or expired refresh token") from exc

    if payload.get("type") != "refresh":
        raise UnauthorizedError("Invalid token type")

    user = db.get(User, uuid.UUID(payload["sub"]))
    if not user or not user.is_active:
        raise UnauthorizedError("User not found or inactive")

    return issue_tokens(user)
