from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

from app.core.config import settings
from app.core.logging import get_logger
from app.integrations.zap.commands import CONTAINER_WORKDIR

logger = get_logger(__name__)

_LOCALHOST_HOSTNAMES = {"localhost", "127.0.0.1", "::1"}


@dataclass
class ZapRunResult:
    exit_code: int
    logs: str
    json_report_path: str | None
    html_report_path: str | None


def resolve_docker_target(url: str) -> str:
    """Rewrite localhost/127.0.0.1 target URLs for the ZAP sibling container.

    ZAP runs as a separate container launched through the host's Docker
    socket, with its own network namespace -- "localhost" from inside it
    means the ZAP container itself, not the developer's machine where the
    app under test is actually listening. `host.docker.internal` is the
    portable way to reach the host: Docker Desktop (Mac/Windows) provides
    it out of the box, and `run_zap_container` below adds the
    `host-gateway` extra_hosts entry so it also resolves on Linux.
    Private IPs and real domains are left untouched -- they're already
    routable from a sibling container.
    """
    parts = urlsplit(url)
    if parts.hostname not in _LOCALHOST_HOSTNAMES:
        return url

    netloc = "host.docker.internal"
    if parts.port:
        netloc += f":{parts.port}"
    if parts.username:
        userinfo = parts.username + (f":{parts.password}" if parts.password else "")
        netloc = f"{userinfo}@{netloc}"

    return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))


def run_zap_container(
    command: list[str], scan_id: str, output_dir: str, timeout_seconds: int = 900
) -> ZapRunResult:
    """Run the OWASP ZAP Docker image with the given wrapper-script command.

    ZAP runs as a *sibling* container launched through the host's Docker
    socket (mounted into this worker), so volume sources must be a named
    Docker volume -- not a path inside this worker container's own
    filesystem, which the host daemon can't see. `command` is expected to
    write its JSON/HTML reports under "<scan_id>/report.{json,html}" inside
    that shared volume; `output_dir` is this worker's own view of the same
    subdirectory, used only to read the results back afterwards.
    """
    import docker

    client = docker.from_env()
    logs = ""
    exit_code = 1
    try:
        container = client.containers.run(
            settings.ZAP_DOCKER_IMAGE,
            command=command,
            volumes={settings.SCAN_OUTPUT_VOLUME_NAME: {"bind": CONTAINER_WORKDIR, "mode": "rw"}},
            working_dir=CONTAINER_WORKDIR,
            detach=True,
            user="zap",
            extra_hosts={"host.docker.internal": "host-gateway"},
        )
        try:
            result = container.wait(timeout=timeout_seconds)
            exit_code = result.get("StatusCode", 1)
            logs = container.logs().decode("utf-8", errors="replace")
        finally:
            container.remove(force=True)
    except Exception as exc:  # docker daemon unreachable, image pull failure, etc.
        logger.exception("ZAP container run failed")
        logs = f"ZAP container execution failed: {exc}"
        exit_code = 1

    from pathlib import Path

    json_path = Path(output_dir) / "report.json"
    html_path = Path(output_dir) / "report.html"

    return ZapRunResult(
        exit_code=exit_code,
        logs=logs,
        json_report_path=str(json_path) if json_path.exists() else None,
        html_report_path=str(html_path) if html_path.exists() else None,
    )


def ping_docker() -> bool:
    try:
        import docker

        client = docker.from_env()
        return bool(client.ping())
    except Exception:
        return False
