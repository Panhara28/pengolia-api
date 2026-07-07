import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from app.core.config import settings

ALLOWED_SCHEMES = {"http", "https"}
LOCAL_HOSTNAMES = {"localhost", "127.0.0.1", "::1"}
PRIVATE_IPV4_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]

SECURITY_SCOPE_SETTING_KEY = "security_scope"


@dataclass
class ValidationResult:
    allowed: bool
    reason: str
    normalized_url: str | None = None


def _get_approved_domains(db: Session | None) -> set[str]:
    if db is None:
        return set()
    from app.models.setting import Setting

    row = db.query(Setting).filter(Setting.key == SECURITY_SCOPE_SETTING_KEY).one_or_none()
    if not row or not row.value_json:
        return set()
    domains = row.value_json.get("approved_domains", [])
    return {d.lower().strip() for d in domains}


def _is_private_ip(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address):
        return ip.is_loopback or ip.is_private
    return any(ip in net for net in PRIVATE_IPV4_RANGES)


def _resolves_to_private_ip(host: str) -> bool:
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False
    for info in infos:
        addr = info[4][0]
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            continue
        if ip.is_loopback or (isinstance(ip, ipaddress.IPv4Address) and any(ip in n for n in PRIVATE_IPV4_RANGES)):
            return True
    return False


def validate_target_url(url: str | None, db: Session | None = None) -> ValidationResult:
    if not url or not url.strip():
        return ValidationResult(False, "Target URL must not be empty")

    url = url.strip()
    try:
        parsed = urlparse(url)
    except ValueError:
        return ValidationResult(False, "Target URL could not be parsed")

    scheme = (parsed.scheme or "").lower()
    if scheme not in ALLOWED_SCHEMES:
        return ValidationResult(False, f"Unsupported protocol '{scheme}'. Only http and https are allowed")

    host = (parsed.hostname or "").lower()
    if not host:
        return ValidationResult(False, "Target URL must include a valid host")

    normalized = parsed._replace(path=parsed.path.rstrip("/") or "").geturl()

    if host in LOCAL_HOSTNAMES:
        if not settings.ALLOW_LOCALHOST:
            return ValidationResult(False, "Localhost targets are disabled in security settings")
        return ValidationResult(True, "Localhost target allowed", normalized)

    if _is_private_ip(host):
        if not settings.ALLOW_PRIVATE_IPS:
            return ValidationResult(False, "Private IP targets are disabled in security settings")
        return ValidationResult(True, "Private IP target allowed", normalized)

    approved_domains = _get_approved_domains(db)
    if host in approved_domains:
        return ValidationResult(True, "Approved internal/staging domain allowed", normalized)

    # Unknown hostname: if it resolves to a private/loopback address, treat as private.
    if settings.ALLOW_PRIVATE_IPS and _resolves_to_private_ip(host):
        return ValidationResult(True, "Hostname resolves to a private/loopback address", normalized)

    if settings.BLOCK_PUBLIC_TARGETS:
        return ValidationResult(
            False,
            f"'{host}' is a public/unapproved target and is blocked by default. "
            "Add it to approved internal/staging domains in settings to allow scanning it.",
        )

    return ValidationResult(True, "Public target allowed (BLOCK_PUBLIC_TARGETS disabled)", normalized)
