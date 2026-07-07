from fastapi import APIRouter, Depends, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_active_user
from app.core.database import get_db
from app.core.permissions import require_role
from app.models.setting import Setting
from app.models.user import User, UserRole
from app.schemas.setting import ScanDefaultSettings, SecurityScopeSettings, SettingRead, SettingUpdate
from app.services import setting_service
from app.services.audit_service import log_action

router = APIRouter(prefix="/settings", tags=["Settings"])

ADMIN_ONLY = (UserRole.ADMIN,)


@router.get("", response_model=list[SettingRead])
def list_settings(db: Session = Depends(get_db), _: User = Depends(get_current_active_user)):
    return db.execute(select(Setting).order_by(Setting.key)).scalars().all()


@router.patch("", response_model=SettingRead)
def update_setting(
    payload: SettingUpdate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*ADMIN_ONLY)),
):
    setting = db.query(Setting).filter(Setting.key == payload.key).one_or_none()
    if not setting:
        setting = Setting(key=payload.key, value_json=payload.value_json, description=payload.description)
        db.add(setting)
    else:
        setting.value_json = payload.value_json
        if payload.description is not None:
            setting.description = payload.description
    db.commit()
    db.refresh(setting)

    log_action(
        db,
        actor_id=current_user.id,
        action="settings.changed",
        resource_type="setting",
        resource_id=payload.key,
        request=request,
    )
    return setting


@router.get("/security-scope", response_model=SecurityScopeSettings)
def get_security_scope(db: Session = Depends(get_db), _: User = Depends(get_current_active_user)):
    setting = setting_service.get_security_scope(db)
    return SecurityScopeSettings(**setting.value_json)


@router.patch("/security-scope", response_model=SecurityScopeSettings)
def update_security_scope(
    payload: SecurityScopeSettings,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*ADMIN_ONLY)),
):
    setting = setting_service.get_security_scope(db)
    setting = setting_service.update_setting_value(db, setting, payload.model_dump())
    log_action(
        db,
        actor_id=current_user.id,
        action="settings.changed",
        resource_type="setting",
        resource_id=setting_service.SECURITY_SCOPE_KEY,
        request=request,
    )
    return SecurityScopeSettings(**setting.value_json)


@router.get("/scan-defaults", response_model=ScanDefaultSettings)
def get_scan_defaults(db: Session = Depends(get_db), _: User = Depends(get_current_active_user)):
    setting = setting_service.get_scan_defaults(db)
    return ScanDefaultSettings(**setting.value_json)


@router.patch("/scan-defaults", response_model=ScanDefaultSettings)
def update_scan_defaults(
    payload: ScanDefaultSettings,
    db: Session = Depends(get_db),
    _: User = Depends(require_role(UserRole.ADMIN, UserRole.SECURITY_ENGINEER)),
):
    setting = setting_service.get_scan_defaults(db)
    setting = setting_service.update_setting_value(db, setting, payload.model_dump(mode="json"))
    return ScanDefaultSettings(**setting.value_json)
