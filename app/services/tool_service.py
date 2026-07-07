import uuid
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.core.exceptions import NotFoundError
from app.models.tool import ToolIntegration, ToolStatus


def get_tool_or_404(db: Session, tool_id: uuid.UUID) -> ToolIntegration:
    tool = db.get(ToolIntegration, tool_id)
    if not tool:
        raise NotFoundError("Tool")
    return tool


def update_tool(db: Session, tool: ToolIntegration, payload) -> ToolIntegration:
    data = payload.model_dump(exclude_unset=True)
    for field, value in data.items():
        setattr(tool, field, value)
    db.commit()
    db.refresh(tool)
    return tool


def test_connection(tool: ToolIntegration) -> tuple[ToolStatus, str]:
    if tool.slug == "owasp-zap":
        from app.integrations.zap.client import ping_docker

        if ping_docker():
            return ToolStatus.CONNECTED, "Docker daemon reachable; OWASP ZAP image can be run on demand."
        return ToolStatus.ERROR, "Could not reach the Docker daemon. Ensure Docker is running and the socket is mounted."

    return ToolStatus.NOT_CONFIGURED, f"{tool.name} integration is not yet implemented; placeholder only."


def record_test_connection(db: Session, tool: ToolIntegration) -> tuple[ToolStatus, str]:
    status, detail = test_connection(tool)
    tool.status = status
    tool.last_used_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(tool)
    return status, detail
