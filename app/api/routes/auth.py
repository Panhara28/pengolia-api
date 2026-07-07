from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.orm import Session

from app.api.deps import get_current_active_user
from app.core.config import settings
from app.core.cookies import clear_auth_cookies, set_auth_cookies
from app.core.database import get_db
from app.core.exceptions import UnauthorizedError
from app.core.limiter import rate_limit
from app.core.security import hash_password
from app.schemas.auth import (
    AuthUserResponse,
    LoginRequest,
    LogoutResponse,
    ProfileUpdate,
    RefreshResponse,
    RegisterRequest,
)
from app.schemas.user import UserRead
from app.services import auth_service
from app.services.audit_service import log_action
from app.models.user import User

router = APIRouter(prefix="/auth", tags=["Auth"])


@router.post("/register", response_model=AuthUserResponse, status_code=201)
@rate_limit("5/hour")
def register(
    payload: RegisterRequest, request: Request, response: Response, db: Session = Depends(get_db)
):
    user = auth_service.register_user(db, payload.email, payload.full_name, payload.password)
    access_token, refresh_token = auth_service.issue_tokens(user)
    set_auth_cookies(response, access_token, refresh_token)
    log_action(
        db,
        actor_id=user.id,
        action="user.register",
        resource_type="user",
        resource_id=str(user.id),
        request=request,
    )
    return AuthUserResponse(user=UserRead.model_validate(user))


@router.post("/login", response_model=AuthUserResponse)
@rate_limit("10/minute")
def login(payload: LoginRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    user = auth_service.authenticate_user(db, payload.email, payload.password)
    access_token, refresh_token = auth_service.issue_tokens(user)
    set_auth_cookies(response, access_token, refresh_token)
    log_action(
        db,
        actor_id=user.id,
        action="user.login",
        resource_type="user",
        resource_id=str(user.id),
        request=request,
    )
    return AuthUserResponse(user=UserRead.model_validate(user))


@router.post("/refresh", response_model=RefreshResponse)
@rate_limit("30/minute")
def refresh(request: Request, response: Response, db: Session = Depends(get_db)):
    refresh_token = request.cookies.get(settings.REFRESH_TOKEN_COOKIE_NAME)
    if not refresh_token:
        raise UnauthorizedError("No refresh token provided")
    access_token, new_refresh_token = auth_service.refresh_access_token(db, refresh_token)
    set_auth_cookies(response, access_token, new_refresh_token)
    return RefreshResponse()


@router.get("/me", response_model=UserRead)
def me(current_user: User = Depends(get_current_active_user)):
    return current_user


@router.patch("/me", response_model=UserRead)
def update_me(
    payload: ProfileUpdate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    if payload.full_name is not None:
        current_user.full_name = payload.full_name
    if payload.password:
        current_user.hashed_password = hash_password(payload.password)

    db.commit()
    db.refresh(current_user)

    log_action(
        db,
        actor_id=current_user.id,
        action="user.updated_own_profile",
        resource_type="user",
        resource_id=str(current_user.id),
        request=request,
    )
    return current_user


@router.post("/logout", response_model=LogoutResponse)
def logout(response: Response, current_user: User = Depends(get_current_active_user)):
    clear_auth_cookies(response)
    return LogoutResponse()
