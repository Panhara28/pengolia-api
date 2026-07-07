import uuid

from fastapi import Request
from sqlalchemy.orm import Session

from app.core.exceptions import InvalidTargetError, NotFoundError, ScopeNotConfirmedError
from app.models.project import Project
from app.models.user import User
from app.services import target_validator
from app.services.audit_service import log_action


def create_project(db: Session, payload, current_user: User, request: Request | None = None) -> Project:
    result = target_validator.validate_target_url(payload.target_url, db=db)
    if not result.allowed:
        raise InvalidTargetError(result.reason)

    project = Project(
        name=payload.name,
        target_url=result.normalized_url,
        environment=payload.environment,
        owner_id=payload.owner_id or current_user.id,
        description=payload.description,
        scope_confirmed=payload.scope_confirmed,
    )
    db.add(project)
    db.commit()
    db.refresh(project)

    log_action(
        db,
        actor_id=current_user.id,
        action="project.created",
        resource_type="project",
        resource_id=str(project.id),
        metadata={"target_url": project.target_url},
        request=request,
    )
    return project


def get_project_or_404(db: Session, project_id: uuid.UUID) -> Project:
    project = db.get(Project, project_id)
    if not project or project.deleted_at is not None:
        raise NotFoundError("Project")
    return project


def update_project(db: Session, project: Project, payload) -> Project:
    data = payload.model_dump(exclude_unset=True)

    if "target_url" in data and data["target_url"]:
        result = target_validator.validate_target_url(data["target_url"], db=db)
        if not result.allowed:
            raise InvalidTargetError(result.reason)
        data["target_url"] = result.normalized_url

    for field, value in data.items():
        setattr(project, field, value)

    db.commit()
    db.refresh(project)
    return project


def soft_delete_project(db: Session, project: Project) -> None:
    from datetime import datetime, timezone

    project.deleted_at = datetime.now(timezone.utc)
    db.commit()


def confirm_scope(db: Session, project: Project, current_user: User, request: Request | None = None) -> Project:
    project.scope_confirmed = True
    db.commit()
    db.refresh(project)

    log_action(
        db,
        actor_id=current_user.id,
        action="project.scope_confirmed",
        resource_type="project",
        resource_id=str(project.id),
        request=request,
    )
    return project


def ensure_scope_confirmed(project: Project) -> None:
    if not project.scope_confirmed:
        raise ScopeNotConfirmedError()
