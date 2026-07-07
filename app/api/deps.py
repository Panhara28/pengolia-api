import uuid

from fastapi import Depends, Request
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.core.exceptions import UnauthorizedError
from app.core.security import decode_token
from app.models.user import User

# auto_error=False so this doesn't 401 before we've had a chance to check the
# httpOnly cookie too -- the cookie is the primary path for the browser app,
# this bearer header is kept for API tooling/tests/Swagger's Authorize button.
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/v1/auth/login", auto_error=False)


def get_current_user(
    request: Request,
    bearer_token: str | None = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    # Explicit bearer header wins over the ambient cookie when both are
    # present -- an intentionally-provided credential shouldn't be silently
    # shadowed by whatever cookie happens to be sitting in the client (this
    # matters for API tooling/tests using a Bearer header on a client whose
    # cookie jar holds a different, more recent session).
    token = bearer_token or request.cookies.get(settings.ACCESS_TOKEN_COOKIE_NAME)
    if not token:
        raise UnauthorizedError()
    try:
        payload = decode_token(token)
    except ValueError as exc:
        raise UnauthorizedError(str(exc)) from exc

    if payload.get("type") != "access":
        raise UnauthorizedError("Invalid token type")

    user_id = payload.get("sub")
    try:
        user = db.get(User, uuid.UUID(user_id))
    except (ValueError, TypeError) as exc:
        raise UnauthorizedError("Invalid token subject") from exc

    if user is None:
        raise UnauthorizedError("User not found")
    return user


def get_current_active_user(current_user: User = Depends(get_current_user)) -> User:
    if not current_user.is_active:
        raise UnauthorizedError("User account is inactive")
    return current_user
