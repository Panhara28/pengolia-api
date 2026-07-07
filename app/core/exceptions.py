from fastapi import Request, status
from fastapi.responses import JSONResponse


class AppError(Exception):
    status_code: int = status.HTTP_400_BAD_REQUEST
    code: str = "APP_ERROR"

    def __init__(self, detail: str, field: str | None = None, code: str | None = None):
        self.detail = detail
        self.field = field
        if code:
            self.code = code
        super().__init__(detail)


class InvalidCredentialsError(AppError):
    status_code = status.HTTP_401_UNAUTHORIZED
    code = "INVALID_CREDENTIALS"

    def __init__(self, detail: str = "Invalid email or password"):
        super().__init__(detail)


class TooManyAttemptsError(AppError):
    status_code = status.HTTP_429_TOO_MANY_REQUESTS
    code = "ACCOUNT_LOCKED"

    def __init__(self, detail: str = "Too many failed login attempts. Try again later."):
        super().__init__(detail)


class UnauthorizedError(AppError):
    status_code = status.HTTP_401_UNAUTHORIZED
    code = "UNAUTHORIZED"

    def __init__(self, detail: str = "Not authenticated"):
        super().__init__(detail)


class ForbiddenError(AppError):
    status_code = status.HTTP_403_FORBIDDEN
    code = "FORBIDDEN"

    def __init__(self, detail: str = "You do not have permission to perform this action"):
        super().__init__(detail)


class NotFoundError(AppError):
    status_code = status.HTTP_404_NOT_FOUND
    code = "NOT_FOUND"

    def __init__(self, resource: str = "Resource"):
        super().__init__(f"{resource} not found")


class ConflictError(AppError):
    status_code = status.HTTP_409_CONFLICT
    code = "CONFLICT"


class InvalidTargetError(AppError):
    status_code = status.HTTP_422_UNPROCESSABLE_ENTITY
    code = "INVALID_TARGET_URL"

    def __init__(self, detail: str = "Invalid target URL", field: str | None = "target_url"):
        super().__init__(detail, field=field)


class UnsafeTargetBlockedError(AppError):
    status_code = status.HTTP_403_FORBIDDEN
    code = "UNSAFE_TARGET_BLOCKED"

    def __init__(self, detail: str = "Target is not an approved local/staging/private target"):
        super().__init__(detail, field="target_url")


class ScanAlreadyRunningError(ConflictError):
    code = "SCAN_ALREADY_RUNNING"

    def __init__(self, detail: str = "A scan is already running for this project"):
        super().__init__(detail)


class ToolNotConfiguredError(AppError):
    status_code = status.HTTP_409_CONFLICT
    code = "TOOL_NOT_CONFIGURED"

    def __init__(self, detail: str = "Tool is not configured"):
        super().__init__(detail)


class ScopeNotConfirmedError(AppError):
    status_code = status.HTTP_403_FORBIDDEN
    code = "SCOPE_NOT_CONFIRMED"

    def __init__(self, detail: str = "Project scope must be confirmed before scanning"):
        super().__init__(detail)


async def app_error_handler(request: Request, exc: AppError) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail, "code": exc.code, "field": exc.field},
    )


def register_exception_handlers(app) -> None:
    app.add_exception_handler(AppError, app_error_handler)
