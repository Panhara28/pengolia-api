from pydantic import BaseModel

from app.schemas.common import AppEmailStr
from app.schemas.user import UserRead


class RegisterRequest(BaseModel):
    email: AppEmailStr
    full_name: str
    password: str


class LoginRequest(BaseModel):
    email: AppEmailStr
    password: str


class LogoutResponse(BaseModel):
    detail: str = "Logged out successfully"


class RefreshResponse(BaseModel):
    detail: str = "Token refreshed"


class AuthUserResponse(BaseModel):
    user: UserRead


class ProfileUpdate(BaseModel):
    # Deliberately narrower than the admin-only UserUpdate schema -- no
    # role/is_active fields, so there's no path for a user to escalate their
    # own privileges through this self-service endpoint.
    full_name: str | None = None
    password: str | None = None
