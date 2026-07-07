from sqlalchemy.orm import Session

from app.models.setting import Setting
from app.schemas.setting import ScanDefaultSettings, SecurityScopeSettings

SECURITY_SCOPE_KEY = "security_scope"
SCAN_DEFAULTS_KEY = "scan_defaults"


def get_or_create(db: Session, key: str, default: dict, description: str = "") -> Setting:
    setting = db.query(Setting).filter(Setting.key == key).one_or_none()
    if setting:
        return setting

    setting = Setting(key=key, value_json=default, description=description)
    db.add(setting)
    db.commit()
    db.refresh(setting)
    return setting


def get_security_scope(db: Session) -> Setting:
    return get_or_create(
        db,
        SECURITY_SCOPE_KEY,
        SecurityScopeSettings().model_dump(),
        "Controls which scan targets are considered in-scope.",
    )


def get_scan_defaults(db: Session) -> Setting:
    return get_or_create(
        db,
        SCAN_DEFAULTS_KEY,
        ScanDefaultSettings().model_dump(mode="json"),
        "Default parameters applied to newly created scans.",
    )


def update_setting_value(db: Session, setting: Setting, value_json: dict) -> Setting:
    setting.value_json = value_json
    db.commit()
    db.refresh(setting)
    return setting
