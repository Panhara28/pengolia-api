import uuid

from fastapi import APIRouter, Depends, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.exceptions import ConflictError, ForbiddenError, NotFoundError
from app.core.permissions import require_role
from app.core.security import hash_password
from app.models.user import User, UserRole
from app.schemas.common import Page, PageParams, build_page, paginate
from app.schemas.user import UserCreate, UserRead, UserUpdate
from app.services.audit_service import log_action

router = APIRouter(prefix="/users", tags=["Users"])


@router.get("", response_model=Page[UserRead])
def list_users(
    params: PageParams = Depends(),
    db: Session = Depends(get_db),
    _: User = Depends(require_role(UserRole.ADMIN)),
):
    stmt = select(User)
    if params.search:
        stmt = stmt.where(User.email.ilike(f"%{params.search}%"))
    stmt = stmt.order_by(User.created_at.desc())
    items, total = paginate(db, stmt, params)
    return build_page(items, total, params)


@router.get("/{user_id}", response_model=UserRead)
def get_user(
    user_id: uuid.UUID,
    db: Session = Depends(get_db),
    _: User = Depends(require_role(UserRole.ADMIN)),
):
    user = db.get(User, user_id)
    if not user:
        raise NotFoundError("User")
    return user


@router.post("", response_model=UserRead, status_code=201)
def create_user(
    payload: UserCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN)),
):
    existing = db.execute(select(User).where(User.email == payload.email)).scalar_one_or_none()
    if existing:
        raise ConflictError("A user with this email already exists", code="EMAIL_TAKEN")

    user = User(
        email=payload.email,
        full_name=payload.full_name,
        hashed_password=hash_password(payload.password),
        role=payload.role,
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    log_action(
        db,
        actor_id=current_user.id,
        action="user.created",
        resource_type="user",
        resource_id=str(user.id),
        request=request,
    )
    return user


@router.patch("/{user_id}", response_model=UserRead)
def update_user(
    user_id: uuid.UUID,
    payload: UserUpdate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN)),
):
    user = db.get(User, user_id)
    if not user:
        raise NotFoundError("User")

    if user_id == current_user.id:
        if payload.role is not None and payload.role != current_user.role:
            raise ForbiddenError("You cannot change your own role")
        if payload.is_active is False:
            raise ForbiddenError("You cannot deactivate your own account")

    if payload.full_name is not None:
        user.full_name = payload.full_name
    if payload.role is not None:
        user.role = payload.role
    if payload.is_active is not None:
        user.is_active = payload.is_active
    if payload.password:
        user.hashed_password = hash_password(payload.password)

    db.commit()
    db.refresh(user)

    log_action(
        db,
        actor_id=current_user.id,
        action="user.updated",
        resource_type="user",
        resource_id=str(user.id),
        request=request,
    )
    return user
