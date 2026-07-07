from app.models.finding import FindingSeverity
from app.models.project import RiskLevel

SEVERITY_WEIGHTS: dict[FindingSeverity, float] = {
    FindingSeverity.CRITICAL: 10.0,
    FindingSeverity.HIGH: 7.0,
    FindingSeverity.MEDIUM: 4.0,
    FindingSeverity.LOW: 2.0,
    FindingSeverity.INFORMATIONAL: 0.5,
}

# Normalization ceiling: the weighted score at which risk is considered saturated (100).
_MAX_REFERENCE_SCORE = 50.0


def calculate_risk_score(severities: list[FindingSeverity]) -> float:
    if not severities:
        return 0.0
    raw = sum(SEVERITY_WEIGHTS[s] for s in severities)
    normalized = min(100.0, (raw / _MAX_REFERENCE_SCORE) * 100.0)
    return round(normalized, 2)


def risk_level_for_score(score: float) -> RiskLevel:
    if score <= 20:
        return RiskLevel.LOW
    if score <= 50:
        return RiskLevel.MEDIUM
    if score <= 80:
        return RiskLevel.HIGH
    return RiskLevel.CRITICAL
