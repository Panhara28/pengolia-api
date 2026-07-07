import json
from pathlib import Path
from typing import Any


def parse_zap_json_report(file_path: str) -> list[dict[str, Any]]:
    """Parse a ZAP JSON report (as produced by zap-baseline.py -J) into a flat
    list of raw alert dicts, one per affected URL instance."""
    path = Path(file_path)
    if not path.exists():
        return []

    data = json.loads(path.read_text())
    alerts: list[dict[str, Any]] = []

    for site in data.get("site", []):
        site_url = site.get("@name", "")
        for alert in site.get("alerts", []):
            instances = alert.get("instances", [{}])
            for instance in instances:
                alerts.append(
                    {
                        "name": alert.get("name", "Unknown Finding"),
                        "riskcode": alert.get("riskcode", "1"),
                        "riskdesc": alert.get("riskdesc", ""),
                        "confidence": alert.get("confidence", "2"),
                        "desc": alert.get("desc", ""),
                        "solution": alert.get("solution", ""),
                        "reference": alert.get("reference", ""),
                        "cweid": alert.get("cweid", ""),
                        "wascid": alert.get("wascid", ""),
                        "uri": instance.get("uri") or site_url,
                        "evidence": instance.get("evidence", ""),
                    }
                )
    return alerts
