import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.exceptions import NotFoundError
from app.core.logging import get_logger
from app.core.scoring import risk_level_for_score
from app.models.finding import Finding
from app.models.project import Project
from app.models.report import Report, ReportFormat
from app.models.scan import Scan
from app.models.user import User
from app.services.owasp_mapper import OWASP_CATEGORIES, map_alert_name_to_category

logger = get_logger(__name__)

TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"
_env = Environment(
    loader=FileSystemLoader(str(TEMPLATES_DIR)),
    autoescape=select_autoescape(["html"]),
)

TOOLS_USED = ["OWASP ZAP (baseline scan)"]

# Ordered worst-to-best so remediation-plan and severity-table rows have a
# stable, risk-first sequence regardless of dict/insertion order.
SEVERITY_ORDER = ["critical", "high", "medium", "low", "informational"]

# Suggested fix-by windows per severity -- a common baseline (e.g. similar to
# PCI-DSS/vendor SLA conventions), not a hard compliance requirement. None
# means "no fixed deadline, address at next convenient release."
REMEDIATION_SLA_DAYS = {
    "critical": 7,
    "high": 30,
    "medium": 90,
    "low": 180,
    "informational": None,
}

SCAN_TYPE_METHODOLOGY = {
    "passive_baseline_scan": (
        "A passive baseline scan was performed: the target was crawled and "
        "observed traffic was analyzed for issues (missing security headers, "
        "cookie flags, information disclosure, etc.). No requests designed to "
        "actively probe or alter application state were sent."
    ),
    "authenticated_scan": (
        "An authenticated scan was performed using test credentials supplied "
        "for this engagement, allowing coverage of logged-in application "
        "areas in addition to the passive checks described above."
    ),
    "api_scan": (
        "An API-focused scan was performed against the target's API surface, "
        "using its OpenAPI/API definition to enumerate and test endpoints."
    ),
    "full_local_staging_scan": (
        "A full local/staging assessment was performed, combining the passive "
        "baseline checks with a broader ruleset appropriate for non-production "
        "environments. No exploit payloads or destructive/DoS-style tests were used."
    ),
}


def _dedup_preserve_order(values: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered = []
    for v in values:
        if v and v not in seen:
            seen.add(v)
            ordered.append(v)
    return ordered


def _parse_references(references_json: dict | None) -> dict:
    references_json = references_json or {}
    raw_refs = references_json.get("reference") or ""
    # ZAP's `reference` field is typically newline-separated URLs.
    urls = [line.strip() for line in raw_refs.splitlines() if line.strip()]
    return {
        "urls": urls,
        "cweid": references_json.get("cweid") or None,
        "wascid": references_json.get("wascid") or None,
    }


def _build_remediation_plan(findings: list[Finding]) -> list[dict]:
    """One entry per severity actually present in this scan's findings,
    listing that severity's real recommendations (deduped, not a static
    boilerplate list) and a suggested remediation SLA."""
    by_severity: dict[str, list[Finding]] = {}
    for f in findings:
        by_severity.setdefault(f.severity.value, []).append(f)

    plan = []
    for severity in SEVERITY_ORDER:
        group = by_severity.get(severity)
        if not group:
            continue
        recommendations = _dedup_preserve_order([f.recommendation or "" for f in group])
        sla_days = REMEDIATION_SLA_DAYS.get(severity)
        plan.append(
            {
                "severity": severity,
                "count": len(group),
                "sla_days": sla_days,
                "recommendations": recommendations or ["No specific remediation guidance was provided by the scanner for this finding."],
            }
        )
    return plan


def _build_context(project: Project, scan: Scan, findings: list[Finding]) -> dict:
    findings_by_severity: dict[str, int] = {}
    category_counts: dict[str, int] = {}
    for f in findings:
        findings_by_severity[f.severity.value] = findings_by_severity.get(f.severity.value, 0) + 1
        code = f.owasp_category or map_alert_name_to_category(f.title)
        category_counts[code] = category_counts.get(code, 0) + 1

    owasp_coverage = [
        {
            "code": code,
            "name": name,
            "finding_count": category_counts.get(code, 0),
            "in_scope": scan.selected_owasp_categories is None or code in (scan.selected_owasp_categories or []),
        }
        for code, name in OWASP_CATEGORIES.items()
    ]

    findings_with_extras = [
        {"finding": f, "references": _parse_references(f.references_json)} for f in findings
    ]

    risk_score = scan.risk_score
    critical_count = findings_by_severity.get("critical", 0)
    high_count = findings_by_severity.get("high", 0)
    headline_risk = (
        f"including {critical_count} critical and {high_count} high-severity issue(s) requiring prompt attention"
        if critical_count or high_count
        else "with no critical or high-severity issues identified"
    )
    executive_summary = (
        f"This report summarizes the results of an authorized {scan.scan_type.value.replace('_', ' ')} "
        f"performed against {project.name} ({project.target_url}) in the {project.environment.value} "
        f"environment. {len(findings)} finding(s) were identified, {headline_risk}. "
        f"The overall risk score for this assessment is {risk_score}/100 ({risk_level_for_score(risk_score).value})."
    )

    return {
        "project": project,
        "scan": scan,
        "findings": findings,
        "findings_with_extras": findings_with_extras,
        "findings_by_severity": findings_by_severity,
        "owasp_coverage": owasp_coverage,
        "tools_used": TOOLS_USED,
        "risk_score": risk_score,
        "risk_level": risk_level_for_score(risk_score).value,
        "total_findings": len(findings),
        "executive_summary": executive_summary,
        "methodology_text": SCAN_TYPE_METHODOLOGY.get(
            scan.scan_type.value,
            "This assessment was performed using automated passive/authorized scanning tools.",
        ),
        "remediation_plan": _build_remediation_plan(findings),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def render_html_report(project: Project, scan: Scan, findings: list[Finding]) -> str:
    template = _env.get_template("report.html")
    return template.render(**_build_context(project, scan, findings))


def render_pdf_report(html_content: str, output_path: str) -> bool:
    """Render `html_content` to a PDF at output_path. Returns False (and logs a
    warning) instead of raising if WeasyPrint's native dependencies aren't
    available in this environment, so local dev without system libs still
    works -- the HTML report remains available either way."""
    try:
        from weasyprint import HTML

        HTML(string=html_content).write_pdf(output_path)
        return True
    except Exception:
        logger.warning(
            "PDF generation unavailable (WeasyPrint or its system libraries are "
            "not installed) -- falling back to HTML-only report.",
            exc_info=True,
        )
        return False


def generate_report(db: Session, scan: Scan, current_user: User, name: str | None = None) -> Report:
    project = db.get(Project, scan.project_id)
    findings = db.execute(select(Finding).where(Finding.scan_id == scan.id)).scalars().all()

    html_content = render_html_report(project, scan, findings)

    report_id = uuid.uuid4()
    output_dir = os.path.join(settings.REPORT_OUTPUT_DIR, str(scan.project_id))
    os.makedirs(output_dir, exist_ok=True)

    html_path = os.path.join(output_dir, f"{report_id}.html")
    with open(html_path, "w", encoding="utf-8") as fh:
        fh.write(html_content)

    pdf_path = os.path.join(output_dir, f"{report_id}.pdf")
    has_pdf = render_pdf_report(html_content, pdf_path)
    if not has_pdf and os.path.exists(pdf_path):
        os.remove(pdf_path)

    report = Report(
        id=report_id,
        scan_id=scan.id,
        project_id=scan.project_id,
        name=name or f"{project.name} Security Report",
        format=ReportFormat.PDF if has_pdf else ReportFormat.HTML,
        file_path=html_path,
        executive_summary=_build_context(project, scan, findings)["executive_summary"],
        risk_score=scan.risk_score,
        total_findings=len(findings),
        generated_by=current_user.id,
        generated_at=datetime.now(timezone.utc),
    )
    db.add(report)
    db.commit()
    db.refresh(report)
    return report


def get_report_or_404(db: Session, report_id: uuid.UUID) -> Report:
    report = db.get(Report, report_id)
    if not report:
        raise NotFoundError("Report")
    return report


def resolve_download_path(report: Report, fmt: str) -> str:
    base, _ = os.path.splitext(report.file_path)
    candidate = f"{base}.{fmt}"
    if not os.path.exists(candidate):
        raise NotFoundError(f"{fmt.upper()} report file")
    return candidate
