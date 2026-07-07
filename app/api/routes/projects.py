import uuid

from fastapi import APIRouter, Depends, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_active_user
from app.core.database import get_db
from app.core.permissions import require_role
from app.models.project import Project, ProjectStatus
from app.models.user import User, UserRole
from app.schemas.common import Page, PageParams, build_page, paginate
from app.schemas.project import ProjectCreate, ProjectRead, ProjectUpdate, ScopeConfirmRequest
from app.services import project_service

router = APIRouter(prefix="/projects", tags=["Projects"])

MANAGE_ROLES = (UserRole.ADMIN, UserRole.SECURITY_ENGINEER)


@router.get("", response_model=Page[ProjectRead])
def list_projects(
    params: PageParams = Depends(),
    status_filter: ProjectStatus | None = None,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_active_user),
):
    stmt = select(Project).where(Project.deleted_at.is_(None))
    if params.search:
        stmt = stmt.where(Project.name.ilike(f"%{params.search}%"))
    if status_filter:
        stmt = stmt.where(Project.status == status_filter)
    stmt = stmt.order_by(Project.created_at.desc())
    items, total = paginate(db, stmt, params)
    return build_page(items, total, params)


@router.post("", response_model=ProjectRead, status_code=201)
def create_project(
    payload: ProjectCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*MANAGE_ROLES)),
):
    return project_service.create_project(db, payload, current_user, request)


@router.get("/{project_id}", response_model=ProjectRead)
def get_project(
    project_id: uuid.UUID,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_active_user),
):
    return project_service.get_project_or_404(db, project_id)


@router.patch("/{project_id}", response_model=ProjectRead)
def update_project(
    project_id: uuid.UUID,
    payload: ProjectUpdate,
    db: Session = Depends(get_db),
    _: User = Depends(require_role(*MANAGE_ROLES)),
):
    project = project_service.get_project_or_404(db, project_id)
    return project_service.update_project(db, project, payload)


@router.delete("/{project_id}", status_code=204)
def delete_project(
    project_id: uuid.UUID,
    db: Session = Depends(get_db),
    _: User = Depends(require_role(*MANAGE_ROLES)),
):
    project = project_service.get_project_or_404(db, project_id)
    project_service.soft_delete_project(db, project)


@router.post("/{project_id}/confirm-scope", response_model=ProjectRead)
def confirm_scope(
    project_id: uuid.UUID,
    payload: ScopeConfirmRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    project = project_service.get_project_or_404(db, project_id)
    if current_user.role not in MANAGE_ROLES and project.owner_id != current_user.id:
        from app.core.exceptions import ForbiddenError

        raise ForbiddenError("Only the project owner or an admin/security engineer can confirm scope")
    return project_service.confirm_scope(db, project, current_user, request)
