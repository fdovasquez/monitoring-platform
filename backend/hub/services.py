from django.db import transaction

from .models import Satellite, SatelliteAlert, SatelliteReport, SatelliteServerSnapshot


def clean_text(value, max_length=255):
    if value is None:
        return ""
    return str(value).strip()[:max_length]


def alert_status(status_summary):
    alerts_by_priority = status_summary.get("alerts_by_priority", {})
    critical = int(alerts_by_priority.get("critical") or alerts_by_priority.get("critica") or 0)
    warning = int(alerts_by_priority.get("warning") or alerts_by_priority.get("advertencia") or 0)
    unresolved = int(status_summary.get("alerts_unresolved") or 0)
    if critical:
        return Satellite.STATUS_CRITICAL, critical, warning
    if warning or unresolved:
        return Satellite.STATUS_WARNING, critical, warning
    return Satellite.STATUS_OK, critical, warning


def is_test_report(status_summary):
    return bool(status_summary.get("test"))


def metric_index(metrics):
    indexed = {}
    for metric in metrics:
        if not isinstance(metric, dict):
            continue
        keys = [
            clean_text(metric.get("server")),
            clean_text(metric.get("server_id")),
        ]
        for key in keys:
            if key:
                indexed[key] = metric
    return indexed


@transaction.atomic
def store_report(payload, validated):
    agents = payload.get("agents") if isinstance(payload.get("agents"), list) else []
    metrics = payload.get("metrics") if isinstance(payload.get("metrics"), list) else []
    alerts = payload.get("alerts") if isinstance(payload.get("alerts"), list) else []
    status_summary = payload.get("status") if isinstance(payload.get("status"), dict) else {}
    test_report = is_test_report(status_summary)
    status, critical_alerts, warning_alerts = alert_status(status_summary)

    satellite, created = Satellite.objects.get_or_create(
        satellite_id=validated["satellite_id"],
        defaults={
            "name": validated["satellite_name"],
            "hostname": clean_text(validated.get("hostname")),
            "site_name": clean_text(validated.get("site_name")),
            "status": status,
            "last_report_at": validated["timestamp"],
            "servers_total": int(status_summary.get("servers_total") or len(agents)),
            "servers_online": int(status_summary.get("servers_online") or 0),
            "alerts_unresolved": int(status_summary.get("alerts_unresolved") or 0),
            "critical_alerts": critical_alerts,
            "warning_alerts": warning_alerts,
            "last_payload": payload,
        },
    )

    if not created:
        satellite.name = validated["satellite_name"]
        satellite.hostname = clean_text(validated.get("hostname"))
        satellite.site_name = clean_text(validated.get("site_name"))
        satellite.last_report_at = validated["timestamp"]
        if not test_report:
            satellite.status = status
            satellite.servers_total = int(status_summary.get("servers_total") or len(agents))
            satellite.servers_online = int(status_summary.get("servers_online") or 0)
            satellite.alerts_unresolved = int(status_summary.get("alerts_unresolved") or 0)
            satellite.critical_alerts = critical_alerts
            satellite.warning_alerts = warning_alerts
            satellite.last_payload = payload
        satellite.save()

    report = SatelliteReport.objects.create(
        satellite=satellite,
        report_timestamp=validated["timestamp"],
        source_hostname=clean_text(validated.get("hostname")),
        site_name=clean_text(validated.get("site_name")),
        agents_count=len(agents),
        metrics_count=len(metrics),
        alerts_count=len(alerts),
        status_summary=status_summary,
        payload=payload,
    )

    if test_report:
        return report

    indexed_metrics = metric_index(metrics)
    seen_hosts = []
    for agent in agents:
        if not isinstance(agent, dict):
            continue
        hostname = clean_text(agent.get("hostname") or agent.get("name"))
        if not hostname:
            continue
        source_id = clean_text(agent.get("id"), 80)
        metric = indexed_metrics.get(hostname) or indexed_metrics.get(source_id) or {}
        seen_hosts.append(hostname)
        SatelliteServerSnapshot.objects.update_or_create(
            satellite=satellite,
            hostname=hostname,
            defaults={
                "source_server_id": source_id,
                "name": clean_text(agent.get("name")),
                "ip_address": clean_text(agent.get("ip_address"), 80),
                "group": clean_text(agent.get("group"), 120),
                "os_type": clean_text(agent.get("os_type"), 40),
                "environment": clean_text(agent.get("environment"), 120),
                "owner": clean_text(agent.get("owner")),
                "is_active": bool(agent.get("is_active", True)),
                "last_seen": agent.get("last_seen"),
                "agent_version": clean_text(agent.get("agent_version"), 80),
                "inventory": agent.get("inventory") if isinstance(agent.get("inventory"), dict) else {},
                "latest_metric": metric if isinstance(metric, dict) else {},
                "raw_data": agent,
            },
        )

    SatelliteServerSnapshot.objects.filter(satellite=satellite).exclude(hostname__in=seen_hosts).update(
        is_active=False,
        latest_metric={},
    )

    for alert in alerts:
        if not isinstance(alert, dict):
            continue
        source_alert_id = clean_text(alert.get("id") or f"{alert.get('server', '')}-{alert.get('rule', '')}", 80)
        if not source_alert_id:
            continue
        SatelliteAlert.objects.update_or_create(
            satellite=satellite,
            source_alert_id=source_alert_id,
            defaults={
                "server_hostname": clean_text(alert.get("server")),
                "rule": clean_text(alert.get("rule")),
                "event_type": clean_text(alert.get("event_type"), 120),
                "priority": clean_text(alert.get("priority"), 40),
                "value": clean_text(alert.get("value"), 120),
                "message": clean_text(alert.get("message"), 2000),
                "is_resolved": bool(alert.get("is_resolved", False)),
                "source_created_at": alert.get("created_at"),
                "source_resolved_at": alert.get("resolved_at"),
                "raw_data": alert,
            },
        )

    return report
