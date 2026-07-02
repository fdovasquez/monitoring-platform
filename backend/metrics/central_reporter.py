import json
import logging
import socket
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from django.conf import settings
from django.db.models import Count, Max
from django.utils import timezone

from alerts.models import AlertEvent
from inventory.models import CentralMonitorSettings, Server, SiteSettings
from metrics.models import CentralReportQueue, MetricSample


logger = logging.getLogger(__name__)


class CentralReporterError(Exception):
    pass


class CentralReporterConfigurationError(CentralReporterError):
    pass


class CentralReporterConfig:
    def __init__(
        self,
        enabled,
        api_url,
        satellite_id,
        satellite_name,
        api_token,
        report_interval_seconds,
        timeout_seconds,
        max_batch,
    ):
        self.enabled = enabled
        self.api_url = api_url.rstrip("/") if api_url else ""
        self.satellite_id = satellite_id
        self.satellite_name = satellite_name
        self.api_token = api_token
        self.report_interval_seconds = report_interval_seconds
        self.timeout_seconds = timeout_seconds
        self.max_batch = max_batch


def get_config():
    database_settings = CentralMonitorSettings.load()
    if database_settings.is_configured or database_settings.reporting_enabled:
        return CentralReporterConfig(
            enabled=database_settings.reporting_enabled,
            api_url=database_settings.central_api_url,
            satellite_id=database_settings.satellite_id,
            satellite_name=database_settings.satellite_name,
            api_token=database_settings.get_api_token(),
            report_interval_seconds=database_settings.report_interval_seconds,
            timeout_seconds=database_settings.timeout_seconds,
            max_batch=database_settings.max_batch,
        )
    return CentralReporterConfig(
        enabled=settings.CENTRAL_REPORTING_ENABLED,
        api_url=settings.CENTRAL_API_URL,
        satellite_id=settings.SATELLITE_ID,
        satellite_name=settings.SATELLITE_NAME,
        api_token=settings.API_TOKEN,
        report_interval_seconds=settings.REPORT_INTERVAL_SECONDS,
        timeout_seconds=settings.CENTRAL_REPORT_TIMEOUT_SECONDS,
        max_batch=settings.CENTRAL_REPORT_MAX_BATCH,
    )


def is_enabled():
    return bool(get_config().enabled)


def validate_configuration(config=None):
    config = config or get_config()
    missing = []
    if not config.api_url:
        missing.append("CENTRAL_API_URL")
    if not config.satellite_id:
        missing.append("SATELLITE_ID")
    if not config.satellite_name:
        missing.append("SATELLITE_NAME")
    if not config.api_token:
        missing.append("API_TOKEN")
    if missing:
        raise CentralReporterConfigurationError(f"Faltan variables de reporte central: {', '.join(missing)}")


def report_endpoint(config=None):
    config = config or get_config()
    return f"{config.api_url}/api/v1/satellites/report"


def latest_metric_by_server():
    latest_ids = []
    latest_timestamps = (
        MetricSample.objects.values("server_id")
        .annotate(latest_timestamp=Max("timestamp"))
        .values_list("server_id", "latest_timestamp")
    )
    for server_id, timestamp in latest_timestamps:
        sample = (
            MetricSample.objects.filter(server_id=server_id, timestamp=timestamp)
            .order_by("-created_at")
            .first()
        )
        if sample:
            latest_ids.append(sample.id)
    return {
        sample.server_id: sample
        for sample in MetricSample.objects.select_related("server").filter(id__in=latest_ids)
    }


def serialize_metric(sample):
    if not sample:
        return None
    return {
        "timestamp": sample.timestamp.isoformat(),
        "agent_version": sample.agent_version,
        "cpu_percent": sample.cpu_percent,
        "memory_percent": sample.memory_percent,
        "disk_percent": sample.disk_percent,
        "uptime_seconds": sample.uptime_seconds,
        "payload": sample.payload,
    }


def serialize_server(server, sample):
    inventory = getattr(server, "inventory", None)
    return {
        "id": server.id,
        "hostname": server.hostname,
        "name": server.name,
        "ip_address": server.ip_address,
        "group": server.group.name if server.group else "",
        "os_type": server.os_type,
        "environment": server.environment,
        "owner": server.owner,
        "is_active": server.is_active,
        "last_seen": server.last_seen.isoformat() if server.last_seen else None,
        "agent_version": sample.agent_version if sample else "",
        "inventory": {
            "fqdn": inventory.fqdn if inventory else "",
            "os_name": inventory.os_name if inventory else "",
            "os_version": inventory.os_version if inventory else "",
            "kernel": inventory.kernel if inventory else "",
            "architecture": inventory.architecture if inventory else "",
            "interfaces": inventory.interfaces if inventory else [],
        },
    }


def serialize_alert(event):
    return {
        "id": event.id,
        "rule": event.rule.name,
        "event_type": event.rule.event_type,
        "priority": event.rule.priority,
        "server": event.server.hostname,
        "value": event.value,
        "message": event.message,
        "is_resolved": event.is_resolved,
        "created_at": event.created_at.isoformat(),
        "resolved_at": event.resolved_at.isoformat() if event.resolved_at else None,
    }


def build_payload():
    site_settings = SiteSettings.load()
    servers = list(Server.objects.select_related("group", "inventory").all())
    metrics_by_server = latest_metric_by_server()
    alert_events = list(
        AlertEvent.objects.select_related("rule", "server").order_by("-created_at")[:100]
    )
    unresolved_counts = (
        AlertEvent.objects.filter(is_resolved=False)
        .values("rule__priority")
        .annotate(total=Count("id"))
    )
    status = {
        "servers_total": len(servers),
        "servers_active": sum(1 for server in servers if server.is_active),
        "servers_online": sum(1 for server in servers if server.last_seen),
        "alerts_unresolved": sum(item["total"] for item in unresolved_counts),
        "alerts_by_priority": {item["rule__priority"]: item["total"] for item in unresolved_counts},
        "queued_reports": CentralReportQueue.objects.filter(status=CentralReportQueue.STATUS_PENDING).count(),
    }
    return {
        "satellite_id": get_config().satellite_id,
        "satellite_name": get_config().satellite_name,
        "timestamp": timezone.now().isoformat(),
        "hostname": socket.gethostname(),
        "site_name": site_settings.site_name,
        "agents": [serialize_server(server, metrics_by_server.get(server.id)) for server in servers],
        "metrics": [
            {
                "server": sample.server.hostname,
                "server_id": sample.server_id,
                **serialize_metric(sample),
            }
            for sample in metrics_by_server.values()
        ],
        "alerts": [serialize_alert(event) for event in alert_events],
        "status": status,
    }


def post_payload(payload, config=None):
    config = config or get_config()
    validate_configuration(config)
    body = json.dumps(payload).encode("utf-8")
    request = Request(
        report_endpoint(config),
        data=body,
        headers={
            "Authorization": f"Bearer {config.api_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        method="POST",
    )
    try:
        with urlopen(request, timeout=config.timeout_seconds) as response:
            status_code = response.getcode()
            if 200 <= status_code < 300:
                logger.info("Reporte central enviado correctamente. HTTP %s", status_code)
                return status_code
            raise CentralReporterError(f"Error HTTP {status_code}")
    except HTTPError as exc:
        if exc.code in {401, 403}:
            logger.error("Token invalido al enviar reporte central. HTTP %s", exc.code)
        else:
            logger.error("Error HTTP al enviar reporte central. HTTP %s", exc.code)
        raise CentralReporterError(f"Error HTTP {exc.code}") from exc
    except URLError as exc:
        logger.error("Error de conexion al servidor central: %s", exc.reason)
        raise CentralReporterError(f"Error de conexion: {exc.reason}") from exc
    except TimeoutError as exc:
        logger.error("Timeout al enviar reporte central.")
        raise CentralReporterError("Timeout de conexion") from exc


def enqueue_payload(payload, error_message):
    queued = CentralReportQueue.objects.create(
        payload=payload,
        status=CentralReportQueue.STATUS_PENDING,
        last_error=str(error_message),
    )
    logger.warning("Reporte encolado para reintento. id=%s error=%s", queued.id, error_message)
    return queued


def flush_pending_reports(limit=None):
    config = get_config()
    sent = 0
    failed = 0
    limit = limit or config.max_batch
    pending_reports = CentralReportQueue.objects.filter(status=CentralReportQueue.STATUS_PENDING).order_by("created_at")[:limit]
    for queued_report in pending_reports:
        try:
            post_payload(queued_report.payload, config)
        except CentralReporterError as exc:
            queued_report.attempts += 1
            queued_report.last_error = str(exc)
            queued_report.save(update_fields=["attempts", "last_error", "updated_at"])
            failed += 1
            break
        else:
            queued_report.status = CentralReportQueue.STATUS_SENT
            queued_report.sent_at = timezone.now()
            queued_report.last_error = ""
            queued_report.save(update_fields=["status", "sent_at", "last_error", "updated_at"])
            sent += 1
    return {"sent": sent, "failed": failed}


def run_report_cycle():
    config = get_config()
    if not config.enabled:
        logger.info("Reporte central desactivado por CENTRAL_REPORTING_ENABLED=false.")
        return {"enabled": False, "sent": 0, "queued": 0, "pending_sent": 0, "pending_failed": 0}

    validate_configuration(config)
    pending_result = flush_pending_reports()
    payload = build_payload()
    try:
        post_payload(payload, config)
    except CentralReporterError as exc:
        enqueue_payload(payload, exc)
        return {
            "enabled": True,
            "sent": 0,
            "queued": 1,
            "pending_sent": pending_result["sent"],
            "pending_failed": pending_result["failed"],
            "error": str(exc),
        }
    return {
        "enabled": True,
        "sent": 1,
        "queued": 0,
        "pending_sent": pending_result["sent"],
        "pending_failed": pending_result["failed"],
    }


def test_central_connection():
    config = get_config()
    validate_configuration(config)
    payload = {
        "satellite_id": config.satellite_id,
        "satellite_name": config.satellite_name,
        "timestamp": timezone.now().isoformat(),
        "hostname": socket.gethostname(),
        "site_name": SiteSettings.load().site_name,
        "agents": [],
        "metrics": [],
        "alerts": [],
        "status": {
            "test": True,
            "message": "Prueba funcional desde configuracion del satelite",
        },
    }
    return post_payload(payload, config)
