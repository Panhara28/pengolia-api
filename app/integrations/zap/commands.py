"""Command builders for OWASP ZAP's official baseline/API scan wrapper scripts.

These wrap ZAP's own passive/limited-active scripts (zap-baseline.py,
zap-api-scan.py) that ship inside the official Docker image. No custom
offensive/exploit payloads are constructed here.
"""

CONTAINER_WORKDIR = "/zap/wrk"


def _report_paths(scan_id: str) -> tuple[str, str]:
    # Paths are relative to CONTAINER_WORKDIR and live inside the scan_id
    # subdirectory that scan_service already created in the shared volume,
    # so the API/worker container can read them back at the same relative
    # path under SCAN_OUTPUT_DIR.
    return f"{scan_id}/report.json", f"{scan_id}/report.html"


def build_baseline_command(target_url: str, scan_id: str) -> list[str]:
    json_path, html_path = _report_paths(scan_id)
    return [
        "zap-baseline.py",
        "-t",
        target_url,
        "-J",
        json_path,
        "-r",
        html_path,
        "-I",  # do not fail the container on warnings/alerts found
    ]


def build_api_scan_command(target_url: str, openapi_url: str, scan_id: str) -> list[str]:
    json_path, html_path = _report_paths(scan_id)
    return [
        "zap-api-scan.py",
        "-t",
        openapi_url,
        "-f",
        "openapi",
        "-J",
        json_path,
        "-r",
        html_path,
        "-I",
    ]
