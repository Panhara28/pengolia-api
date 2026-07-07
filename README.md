# PentestFlow API

PentestFlow is a backend for orchestrating **authorized** security scans against
local, private, QA, and staging web applications before they reach production.
It manages projects, scans, findings (mapped to the OWASP Top 10), reports,
tool integrations, users/RBAC, and audit logging.

## Safety disclaimer

**PentestFlow is not a general-purpose internet scanner.** By default it only
allows scanning:

- `localhost`, `127.0.0.1`, `::1`
- Private IP ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`)
- Domains you explicitly add to the approved internal/staging domain list
  (`Settings -> Security Scope`)

Public internet targets are blocked unless you deliberately disable that
protection in settings. Every project scope confirmation, scan start,
cancellation, report generation, and settings change is recorded in the audit
log. The system does not ship offensive/exploit payload libraries -- it
orchestrates OWASP ZAP's passive/baseline scanning profile and produces
developer-friendly remediation guidance, not attack tooling. Only run this
against systems you own or are explicitly authorized to test.

## Tech stack

- **API**: FastAPI, Pydantic v2
- **Database**: PostgreSQL + SQLAlchemy 2.0 (sync) + Alembic migrations
- **Queue**: Redis + Celery (scan execution, report generation)
- **Auth**: JWT (access + refresh) with bcrypt password hashing, role-based access control
- **Scanning**: OWASP ZAP via Docker (docker-py SDK)
- **Reporting**: Jinja2 (HTML) + WeasyPrint (PDF, with automatic HTML-only fallback)

## Roles & permissions

| Role | Capabilities |
|---|---|
| Admin | Manage everything: users, projects, scans, findings, reports, tools, settings, audit logs |
| Security Engineer | Create projects/scans, manage findings, generate reports, manage scan defaults |
| Developer | View projects, run allowed (non-Full) scans, update finding notes/status |
| Viewer | Read-only: dashboards, reports, findings |

## Local setup (without Docker)

```bash
cd pentestflow-api
python3.13 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # edit DATABASE_URL/REDIS_URL for your local Postgres/Redis
```

## Docker setup

```bash
cp .env.example .env
docker compose up --build
```

This starts `postgres`, `redis`, `api` (port 8000), and `celery_worker`
(mounts the host Docker socket so it can launch OWASP ZAP containers on
demand). `celery_beat` is included but commented out since no periodic tasks
are required yet.

## Environment variables

See `.env.example` for the full list. Key ones:

| Variable | Purpose |
|---|---|
| `DATABASE_URL` | SQLAlchemy/psycopg connection string |
| `REDIS_URL` | Celery broker/result backend |
| `JWT_SECRET_KEY` | Sign access/refresh tokens -- **change in production** |
| `ZAP_DOCKER_IMAGE` | OWASP ZAP image used by the scan workers |
| `SCAN_OUTPUT_DIR` / `REPORT_OUTPUT_DIR` | Host-mounted volumes for scan artifacts and reports |
| `ALLOW_LOCALHOST` / `ALLOW_PRIVATE_IPS` / `BLOCK_PUBLIC_TARGETS` | Target validator defaults (overridable at runtime via `/api/v1/settings/security-scope`) |

## Running migrations

```bash
alembic upgrade head
```

To generate a new migration after changing models:

```bash
alembic revision --autogenerate -m "describe the change"
```

## Seeding the database

```bash
python scripts/seed.py
```

Creates 4 users (all with password `ChangeMe123!`):

- `admin@pentestflow.local` (Admin)
- `security@pentestflow.local` (Security Engineer)
- `developer@pentestflow.local` (Developer)
- `viewer@pentestflow.local` (Viewer)

...plus 4 sample projects, default tool integration rows, default settings,
12 sample findings, 2 sample scans, and 1 sample report.

## Running the API

```bash
uvicorn app.main:app --reload --port 8000
```

- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc
- OpenAPI JSON: http://localhost:8000/openapi.json
- Health check: http://localhost:8000/health

## Running the worker

```bash
celery -A app.core.celery_app worker --loglevel=info
```

## Running tests

```bash
pytest
```

Tests run against an in-memory SQLite database and do not require
Postgres/Redis/Docker -- Celery task dispatch is stubbed out in
`app/tests/conftest.py`.

## Example API calls

```bash
# Register + log in
curl -X POST http://localhost:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"me@example.com","full_name":"Me","password":"StrongPass123!"}'

curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"me@example.com","password":"StrongPass123!"}'
# -> { "access_token": "...", "refresh_token": "...", "user": {...} }

TOKEN="<access_token from above>"

# Create a project (localhost target, scope confirmed)
curl -X POST http://localhost:8000/api/v1/projects \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"Local App","target_url":"http://localhost:3000","environment":"local","scope_confirmed":true}'

# Kick off a passive baseline scan
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"project_id":"<project_id>","scan_type":"passive_baseline_scan"}'

# Check findings
curl "http://localhost:8000/api/v1/findings?severity=high" -H "Authorization: Bearer $TOKEN"

# Generate + download a report
curl -X POST http://localhost:8000/api/v1/reports/generate \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"scan_id":"<scan_id>"}'
curl "http://localhost:8000/api/v1/reports/<report_id>/download/html" -H "Authorization: Bearer $TOKEN" -o report.html
```

## Frontend integration notes

- The frontend should call the API under `http://localhost:8000/api/v1`.
- All list endpoints (`projects`, `scans`, `findings`, `reports`, etc.) return
  the standard paginated envelope: `{ items, total, page, page_size, pages }`,
  driven by `?page=&page_size=&search=&sort_by=&sort_order=`.
- All errors follow `{ "detail": "...", "code": "...", "field": "..." }` so
  the frontend can branch on `code` (e.g. `UNSAFE_TARGET_BLOCKED`,
  `SCOPE_NOT_CONFIRMED`, `SCAN_ALREADY_RUNNING`) instead of parsing prose.
- `POST /scans` and `/scans/{id}/rerun` return immediately with
  `{ id, project_id, status: "queued", progress: 0, message }` -- poll
  `GET /scans/{id}` or `/scans/{id}/summary` for progress/results, matching a
  scan-table-with-live-status UI pattern.
- CORS origins are controlled by `CORS_ORIGINS` in `.env` (defaults to
  `http://localhost:3000` and `http://127.0.0.1:3000`).
