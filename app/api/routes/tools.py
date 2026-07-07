import uuid

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_active_user
from app.core.database import get_db
from app.core.permissions import require_role
from app.models.tool import ToolIntegration
from app.models.user import User, UserRole
from app.schemas.tool import ToolRead, ToolTestConnectionResponse, ToolUpdate
from app.services import tool_service

router = APIRouter(prefix="/tools", tags=["Tools"])


@router.get("", response_model=list[ToolRead])
def list_tools(db: Session = Depends(get_db), _: User = Depends(get_current_active_user)):
    return db.execute(select(ToolIntegration).order_by(ToolIntegration.name)).scalars().all()


@router.get("/{tool_id}", response_model=ToolRead)
def get_tool(
    tool_id: uuid.UUID, db: Session = Depends(get_db), _: User = Depends(get_current_active_user)
):
    return tool_service.get_tool_or_404(db, tool_id)


@router.patch("/{tool_id}", response_model=ToolRead)
def update_tool(
    tool_id: uuid.UUID,
    payload: ToolUpdate,
    db: Session = Depends(get_db),
    _: User = Depends(require_role(UserRole.ADMIN)),
):
    tool = tool_service.get_tool_or_404(db, tool_id)
    return tool_service.update_tool(db, tool, payload)


@router.post("/{tool_id}/test-connection", response_model=ToolTestConnectionResponse)
def test_connection(
    tool_id: uuid.UUID,
    db: Session = Depends(get_db),
    _: User = Depends(require_role(UserRole.ADMIN, UserRole.SECURITY_ENGINEER)),
):
    tool = tool_service.get_tool_or_404(db, tool_id)
    status, detail = tool_service.record_test_connection(db, tool)
    return ToolTestConnectionResponse(status=status, detail=detail)
