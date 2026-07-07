from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from app.core.config import settings
from app.core.exceptions import register_exception_handlers
from app.core.limiter import limiter, rate_limit_exceeded_handler
from app.core.logging import configure_logging

configure_logging()

app = FastAPI(
    title=settings.APP_NAME,
    version="0.1.0",
    description=(
        "PentestFlow orchestrates authorized security scans against local, "
        "private, QA, and staging web applications. It is not designed to "
        "scan arbitrary public internet targets."
    ),
    openapi_tags=[
        {"name": "Auth"},
        {"name": "Users"},
        {"name": "Projects"},
        {"name": "Scans"},
        {"name": "Findings"},
        {"name": "Reports"},
        {"name": "OWASP"},
        {"name": "Tools"},
        {"name": "Settings"},
        {"name": "Dashboard"},
        {"name": "Audit Logs"},
    ],
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)
app.add_exception_handler(RateLimitExceeded, rate_limit_exceeded_handler)

register_exception_handlers(app)

from app.api.routes import (  # noqa: E402
    audit_logs,
    auth,
    dashboard,
    findings,
    owasp,
    projects,
    reports,
    scans,
    settings as settings_routes,
    tools,
    users,
)

api_prefix = settings.API_V1_PREFIX
app.include_router(auth.router, prefix=api_prefix)
app.include_router(users.router, prefix=api_prefix)
app.include_router(projects.router, prefix=api_prefix)
app.include_router(scans.router, prefix=api_prefix)
app.include_router(findings.router, prefix=api_prefix)
app.include_router(reports.router, prefix=api_prefix)
app.include_router(owasp.router, prefix=api_prefix)
app.include_router(tools.router, prefix=api_prefix)
app.include_router(settings_routes.router, prefix=api_prefix)
app.include_router(dashboard.router, prefix=api_prefix)
app.include_router(audit_logs.router, prefix=api_prefix)


@app.get("/health", tags=["Health"])
def health_check():
    return {"status": "ok", "app": settings.APP_NAME}
