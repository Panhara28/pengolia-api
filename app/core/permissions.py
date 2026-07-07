from fastapi import Depends

from app.api.deps import get_current_active_user
from app.core.exceptions import ForbiddenError
from app.models.user import User, UserRole

ROLE_HIERARCHY = {
    UserRole.ADMIN: 4,
    UserRole.SECURITY_ENGINEER: 3,
    UserRole.DEVELOPER: 2,
    UserRole.VIEWER: 1,
}


def require_role(*roles: UserRole):
    def dependency(current_user: User = Depends(get_current_active_user)) -> User:
        if current_user.role not in roles:
            raise ForbiddenError(
                f"This action requires one of the following roles: {', '.join(r.value for r in roles)}"
            )
        return current_user

    return dependency
