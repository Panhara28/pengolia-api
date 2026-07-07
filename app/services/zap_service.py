import os
from datetime import datetime, timezone
from typing import Any

from app.core.config import settings
from app.integrations.zap.client import ZapRunResult, resolve_docker_target, run_zap_container
from app.integrations.zap.commands import build_api_scan_command, build_baseline_command
from app.integrations.zap.parser import parse_zap_json_report
from app.models.finding import FindingConfidence, FindingSeverity
from app.services.owasp_mapper import map_alert_name_to_category

RISK_CODE_TO_SEVERITY = {
    "0": FindingSeverity.INFORMATIONAL,
    "1": FindingSeverity.LOW,
    "2": FindingSeverity.MEDIUM,
    "3": FindingSeverity.HIGH,
}

CONFIDENCE_CODE_TO_LEVEL = {
    "0": FindingConfidence.LOW,
    "1": FindingConfidence.LOW,
    "2": FindingConfidence.MEDIUM,
    "3": FindingConfidence.HIGH,
}


def _prepare_output_dir(scan_id: str) -> str:
    output_dir = os.path.join(settings.SCAN_OUTPUT_DIR, scan_id)
    os.makedirs(output_dir, exist_ok=True)
    return output_dir


def run_baseline_scan(target_url: str, scan_id: str, output_dir: str) -> ZapRunResult:
    """Run ZAP's passive baseline scan (zap-baseline.py) against target_url.

    This is a passive/non-intrusive scan only. It must only be pointed at
    localhost, private-network, or explicitly approved staging targets --
    enforced upstream by target_validator before this is ever called.
    """
    command = build_baseline_command(resolve_docker_target(target_url), scan_id)
    return run_zap_container(command, scan_id, output_dir, timeout_seconds=900)


def run_api_scan(target_url: str, openapi_url: str, scan_id: str, output_dir: str) -> ZapRunResult:
    command = build_api_scan_command(resolve_docker_target(target_url), resolve_docker_target(openapi_url), scan_id)
    return run_zap_container(command, scan_id, output_dir, timeout_seconds=900)


def parse_zap_json_report_file(file_path: str) -> list[dict[str, Any]]:
    return parse_zap_json_report(file_path)


def convert_zap_alert_to_finding(alert: dict[str, Any]) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    severity = RISK_CODE_TO_SEVERITY.get(str(alert.get("riskcode", "1")), FindingSeverity.LOW)
    confidence = CONFIDENCE_CODE_TO_LEVEL.get(
        str(alert.get("confidence", "2")), FindingConfidence.MEDIUM
    )
    owasp_category = map_alert_name_to_category(alert.get("name", ""))

    return {
        "title": alert.get("name", "Unknown Finding"),
        "description": alert.get("desc", ""),
        "severity": severity,
        "confidence": confidence,
        "owasp_category": owasp_category,
        "affected_url": alert.get("uri", ""),
        "evidence": alert.get("evidence", ""),
        "impact": alert.get("riskdesc", ""),
        "recommendation": alert.get("solution", ""),
        "references_json": {
            "reference": alert.get("reference", ""),
            "cweid": alert.get("cweid", ""),
            "wascid": alert.get("wascid", ""),
        },
        "first_seen": now,
        "last_seen": now,
    }


def run_full_local_staging_scan(target_url: str, scan_id: str, output_dir: str) -> ZapRunResult:
    """Placeholder for a deeper, still-defensive local/staging scan profile.

    IMPORTANT: This must only ever be invoked after target_validator has
    confirmed the target is localhost/private/approved-staging AND the
    caller has passed explicit safety_confirmed=True (enforced in
    scan_service.create_scan). It must never include exploit payloads or
    unrestricted active-attack modules -- it currently reuses the same
    passive baseline scan profile as a safe default until a dedicated
    authorized "full" ruleset is added.
    """
    command = build_baseline_command(resolve_docker_target(target_url), scan_id)
    return run_zap_container(command, scan_id, output_dir, timeout_seconds=1800)
