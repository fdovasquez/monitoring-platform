import csv
from datetime import timedelta

from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.db.models import Count, OuterRef, Subquery
from django.http import HttpResponse
from django.utils import timezone
from django.views.generic import TemplateView

from alerts.models import AlertEmailLog, AlertEvent, AlertRule, ServerMonitorAssignment
from metrics.models import MetricSample

from .models import Server
from .templatetags.security_tags import security_assessment
from .views import sidebar_context, user_can_manage_devices


class PortalDataMixin:
    online_window = timedelta(minutes=2)

    def latest_samples(self, servers):
        sample_ids = [server.latest_sample_id for server in servers if server.latest_sample_id]
        return MetricSample.objects.in_bulk(sample_ids)

    def server_queryset(self):
        latest_sample_id = MetricSample.objects.filter(server=OuterRef("pk")).order_by("-timestamp").values("id")[:1]
        return (
            Server.objects.select_related("group", "inventory", "runtime_snapshot")
            .annotate(latest_sample_id=Subquery(latest_sample_id))
            .order_by("hostname")
        )

    def server_rows(self):
        servers = list(self.server_queryset())
        samples = self.latest_samples(servers)
        active_alerts = self.alerts_by_server([server.id for server in servers])
        now = timezone.now()
        rows = []
        for server in servers:
            sample = samples.get(server.latest_sample_id)
            alerts = active_alerts.get(server.id, [])
            security = security_assessment(sample)
            inventory = getattr(server, "inventory", None)
            runtime = getattr(server, "runtime_snapshot", None)
            runtime_counts = self.runtime_counts(runtime)
            disk_info = self.disk_info(sample)
            interface_summary = self.interface_summary(inventory)
            applications = self.application_names(runtime)
            rows.append(
                {
                    "server": server,
                    "sample": sample,
                    "online": bool(server.last_seen and server.last_seen >= now - self.online_window),
                    "alerts": alerts,
                    "alert_level": self.alert_level(alerts),
                    "security": security,
                    "risk_score": self.risk_score(server, sample, alerts, security),
                    "inventory": inventory,
                    "runtime": runtime,
                    "os_label": inventory.os_name if inventory and inventory.os_name else server.get_os_type_display(),
                    "ip_label": server.ip_address or (inventory.primary_ip if inventory and inventory.primary_ip else "-"),
                    "serial_label": inventory.serial_number if inventory and inventory.serial_number else "-",
                    "fqdn_label": inventory.fqdn if inventory and inventory.fqdn else server.hostname,
                    "kernel_label": inventory.kernel if inventory and inventory.kernel else "-",
                    "model_label": inventory.model if inventory and inventory.model else "-",
                    "manufacturer_label": inventory.manufacturer if inventory and inventory.manufacturer else "-",
                    "agent_version": sample.agent_version if sample and sample.agent_version else "-",
                    "cpu_label": self.percent_label(sample.cpu_percent if sample else None),
                    "memory_label": self.percent_label(sample.memory_percent if sample else None),
                    "disk_label": self.percent_label(sample.disk_percent if sample else None),
                    "disk_count": disk_info["count"],
                    "disk_peak": disk_info["peak"],
                    "disk_peak_label": self.percent_label(disk_info["peak"]),
                    "interface_summary": interface_summary,
                    "interface_count": len(interface_summary),
                    "service_count": runtime_counts["services"],
                    "process_count": runtime_counts["processes"],
                    "port_count": runtime_counts["ports"],
                    "applications": applications,
                    "application_label": ", ".join(applications[:3]) if applications else "-",
                    "coverage_score": self.coverage_score(inventory, runtime, sample),
                    "coverage_tone": self.coverage_tone(self.coverage_score(inventory, runtime, sample)),
                    "missing_inventory": self.missing_inventory(inventory, runtime, sample),
                }
            )
        return rows

    @staticmethod
    def percent_label(value):
        if value is None:
            return "-"
        try:
            numeric = float(value)
        except (TypeError, ValueError):
            return "-"
        if numeric.is_integer():
            return f"{int(numeric)}%"
        return f"{numeric:.1f}%"

    @staticmethod
    def runtime_counts(runtime):
        if not runtime:
            return {"services": 0, "processes": 0, "ports": 0}
        return {
            "services": len(runtime.services or []),
            "processes": len(runtime.processes or []),
            "ports": len(runtime.ports or []),
        }

    @staticmethod
    def disk_info(sample):
        if not sample or not isinstance(sample.payload, dict):
            return {"count": 0, "peak": sample.disk_percent if sample else None}
        metrics = sample.payload.get("metrics", {})
        disks = metrics.get("disks") if isinstance(metrics, dict) else []
        if not isinstance(disks, list):
            disks = []
        peak = sample.disk_percent
        disk_percents = []
        for disk in disks:
            if not isinstance(disk, dict):
                continue
            try:
                disk_percents.append(float(disk.get("percent")))
            except (TypeError, ValueError):
                continue
        if disk_percents:
            peak = max(disk_percents)
        return {"count": len(disks), "peak": peak}

    @staticmethod
    def interface_summary(inventory):
        if not inventory or not isinstance(inventory.interfaces, list):
            return []
        interfaces = []
        for interface in inventory.interfaces[:4]:
            if not isinstance(interface, dict):
                continue
            ips = interface.get("ips") if isinstance(interface.get("ips"), list) else []
            interfaces.append(
                {
                    "name": interface.get("name") or interface.get("interface") or "interfaz",
                    "mac": interface.get("mac") or "-",
                    "ips": ", ".join(str(ip) for ip in ips[:3]) if ips else "-",
                }
            )
        return interfaces

    @staticmethod
    def application_names(runtime):
        if not runtime or not isinstance(runtime.raw_data, dict):
            return []
        applications = runtime.raw_data.get("applications")
        if not isinstance(applications, dict):
            return []
        return sorted(name.title() for name in applications.keys())

    @staticmethod
    def coverage_score(inventory, runtime, sample):
        checks = [
            bool(inventory),
            bool(inventory and inventory.serial_number),
            bool(inventory and inventory.model),
            bool(inventory and inventory.interfaces),
            bool(runtime),
            bool(runtime and runtime.services),
            bool(runtime and runtime.processes),
            bool(runtime and runtime.ports),
            bool(sample),
            bool(sample and sample.agent_version),
        ]
        return int(sum(1 for check in checks if check) / len(checks) * 100)

    @staticmethod
    def missing_inventory(inventory, runtime, sample):
        missing = []
        if not inventory:
            return ["Inventario tecnico", "Red", "Fabricante/modelo", "Serie", "Dominio"]
        if not inventory.serial_number:
            missing.append("Serie")
        if not inventory.model:
            missing.append("Modelo")
        if not inventory.manufacturer:
            missing.append("Fabricante")
        if not inventory.interfaces:
            missing.append("Interfaces")
        if not inventory.gateway:
            missing.append("Gateway")
        if not runtime:
            missing.append("Runtime")
        elif not runtime.services:
            missing.append("Servicios")
        if not sample:
            missing.append("Metricas")
        elif not sample.agent_version:
            missing.append("Version agente")
        return missing[:5]

    @staticmethod
    def coverage_tone(score):
        if score >= 80:
            return "ok"
        if score >= 55:
            return "warning"
        return "critical"

    @staticmethod
    def alerts_by_server(server_ids):
        result = {server_id: [] for server_id in server_ids}
        if not server_ids:
            return result
        alerts = (
            AlertEvent.objects.select_related("rule", "server")
            .filter(server_id__in=server_ids, is_resolved=False)
            .order_by("-created_at")
        )
        for alert in alerts:
            result.setdefault(alert.server_id, []).append(alert)
        return result

    @staticmethod
    def alert_level(alerts):
        if any(alert.rule.priority == AlertRule.PRIORITY_CRITICAL for alert in alerts):
            return "critical"
        if alerts:
            return "warning"
        return "ok"

    @staticmethod
    def risk_score(server, sample, alerts, security):
        score = 0
        if not server.last_seen or server.last_seen < timezone.now() - timedelta(minutes=2):
            score += 25
        score += sum(25 if alert.rule.priority == AlertRule.PRIORITY_CRITICAL else 12 for alert in alerts[:4])
        score += max(0, 100 - int(security.get("score", 0))) // 2
        if sample and sample.disk_percent and sample.disk_percent >= 90:
            score += 15
        return min(score, 100)

    @staticmethod
    def summarize(rows):
        total = len(rows)
        critical = sum(1 for row in rows if row["alert_level"] == "critical")
        warning = sum(1 for row in rows if row["alert_level"] == "warning")
        ok = sum(1 for row in rows if row["alert_level"] == "ok" and row["online"])
        offline = sum(1 for row in rows if not row["online"])
        avg_security = int(sum(row["security"]["score"] for row in rows) / total) if total else 0
        continuity = int((sum(1 for row in rows if row["online"]) / total) * 100) if total else 0
        compliance = int((sum(1 for row in rows if row["security"]["score"] >= 75) / total) * 100) if total else 0
        return {
            "total": total,
            "critical": critical,
            "warning": warning,
            "ok": ok,
            "offline": offline,
            "avg_security": avg_security,
            "continuity": continuity,
            "compliance": compliance,
            "risk": min(100, critical * 30 + warning * 12 + offline * 20),
        }


class PortalAccessMixin(LoginRequiredMixin, UserPassesTestMixin):
    def test_func(self):
        return user_can_manage_devices(self.request.user)


class ExecutiveDashboardView(PortalAccessMixin, PortalDataMixin, TemplateView):
    template_name = "inventory/executive_dashboard.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        rows = self.server_rows()
        context.update(
            {
                "rows": sorted(rows, key=lambda item: item["risk_score"], reverse=True)[:8],
                "summary": self.summarize(rows),
                "active_incidents": AlertEvent.objects.select_related("rule", "server").filter(is_resolved=False)[:8],
                "recent_notifications": AlertEmailLog.objects.select_related("server").order_by("-created_at")[:6],
                "active_menu": "executive",
            }
        )
        context.update(sidebar_context())
        return context


class CMDBView(PortalAccessMixin, PortalDataMixin, TemplateView):
    template_name = "inventory/cmdb.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        rows = self.server_rows()
        context.update(
            {
                "rows": rows,
                "summary": self.cmdb_summary(rows),
                "groups": self.cmdb_groups(rows),
                "os_groups": self.os_groups(rows),
                "network_diagram": self.network_diagram(rows),
                "relationships": self.relationships(rows),
                "inventory_gaps": self.inventory_gaps(rows),
                "active_menu": "cmdb",
            }
        )
        context.update(sidebar_context())
        return context

    @staticmethod
    def cmdb_groups(rows):
        groups = {}
        for row in rows:
            group_name = row["server"].group.name if row["server"].group else "Sin grupo"
            groups.setdefault(group_name, 0)
            groups[group_name] += 1
        return sorted(groups.items())

    @staticmethod
    def os_groups(rows):
        groups = {}
        for row in rows:
            os_name = row["os_label"] or "Sin sistema"
            groups.setdefault(os_name, 0)
            groups[os_name] += 1
        return sorted(groups.items(), key=lambda item: item[1], reverse=True)[:8]

    @staticmethod
    def cmdb_summary(rows):
        total = len(rows)
        with_inventory = sum(1 for row in rows if row["inventory"])
        with_runtime = sum(1 for row in rows if row["runtime"])
        with_serial = sum(1 for row in rows if row["serial_label"] != "-")
        with_apps = sum(1 for row in rows if row["applications"])
        online = sum(1 for row in rows if row["online"])
        critical = sum(1 for row in rows if row["alert_level"] == "critical")
        warning = sum(1 for row in rows if row["alert_level"] == "warning")
        avg_coverage = int(sum(row["coverage_score"] for row in rows) / total) if total else 0
        return {
            "total": total,
            "with_inventory": with_inventory,
            "with_runtime": with_runtime,
            "with_serial": with_serial,
            "with_apps": with_apps,
            "online": online,
            "offline": total - online,
            "critical": critical,
            "warning": warning,
            "avg_coverage": avg_coverage,
        }

    @staticmethod
    def inventory_gaps(rows):
        gaps = []
        for row in rows:
            if row["missing_inventory"]:
                gaps.append(row)
        return sorted(gaps, key=lambda item: item["coverage_score"])[:8]

    @staticmethod
    def network_diagram(rows):
        groups = {}
        assets = []
        networks = []
        applications = {}

        def asset_sort_key(row):
            alert_order = {"critical": 0, "warning": 1, "ok": 2}
            return (alert_order.get(row["alert_level"], 3), not row["online"], row["server"].hostname)

        for row in sorted(rows, key=asset_sort_key):
            server = row["server"]
            group_name = server.group.name if server.group else "Sin grupo"
            groups.setdefault(group_name, {"name": group_name, "count": 0})
            groups[group_name]["count"] += 1

            if len(assets) < 12:
                assets.append(
                    {
                        "id": server.id,
                        "hostname": server.hostname,
                        "group": group_name,
                        "ip": row["ip_label"],
                        "status": "offline" if not row["online"] else row["alert_level"],
                        "status_label": "Fuera de linea" if not row["online"] else row["alert_level"],
                        "os": row["os_label"],
                        "apps": row["applications"][:2],
                        "ports": row["port_count"],
                        "interfaces": row["interface_count"],
                    }
                )

            if row["ip_label"] != "-" and len(networks) < 12:
                primary_interface = row["interface_summary"][0]["name"] if row["interface_summary"] else "Interfaz no reportada"
                networks.append(
                    {
                        "hostname": server.hostname,
                        "ip": row["ip_label"],
                        "interface": primary_interface,
                        "interfaces": row["interface_count"],
                    }
                )

            runtime = row["runtime"]
            raw_data = runtime.raw_data if runtime and isinstance(runtime.raw_data, dict) else {}
            runtime_apps = raw_data.get("applications") if isinstance(raw_data.get("applications"), dict) else {}
            for app_name, app_data in runtime_apps.items():
                name = app_name.title()
                app_entry = applications.setdefault(name, {"name": name, "assets": set(), "ports": set()})
                app_entry["assets"].add(server.hostname)
                ports = app_data.get("ports", []) if isinstance(app_data, dict) else []
                for port in ports:
                    if not isinstance(port, dict):
                        continue
                    port_label = port.get("local_port") or port.get("port")
                    protocol = (port.get("protocol") or "tcp").upper()
                    if port_label:
                        app_entry["ports"].add(f"{protocol}/{port_label}")

        application_nodes = []
        for app in sorted(applications.values(), key=lambda item: (-len(item["assets"]), item["name"]))[:8]:
            application_nodes.append(
                {
                    "name": app["name"],
                    "asset_count": len(app["assets"]),
                    "ports": sorted(app["ports"])[:4],
                }
            )

        return {
            "groups": sorted(groups.values(), key=lambda item: (-item["count"], item["name"]))[:8],
            "assets": assets,
            "networks": networks,
            "applications": application_nodes,
            "asset_count": len(rows),
            "relationship_count": sum(len(row["applications"]) + row["interface_count"] + (1 if row["ip_label"] != "-" else 0) for row in rows),
        }

    @staticmethod
    def relationships(rows):
        relationships = []
        for row in rows:
            server = row["server"]
            if server.group:
                relationships.append((server.hostname, "pertenece a grupo", server.group.name))
            runtime = row["runtime"]
            raw_data = runtime.raw_data if runtime and isinstance(runtime.raw_data, dict) else {}
            applications = raw_data.get("applications") if isinstance(raw_data.get("applications"), dict) else {}
            for name, app in applications.items():
                relationships.append((server.hostname, "ejecuta aplicacion", name.title()))
                for port in app.get("ports", [])[:4] if isinstance(app, dict) else []:
                    relationships.append((name.title(), "publica puerto", str(port.get("local_port", "-"))))
            if row["ip_label"] != "-":
                relationships.append((server.hostname, "tiene direccion IP", row["ip_label"]))
            for interface in row["interface_summary"][:2]:
                relationships.append((server.hostname, "usa interfaz", interface["name"]))
        return relationships[:40]


class IncidentCenterView(PortalAccessMixin, PortalDataMixin, TemplateView):
    template_name = "inventory/incidents.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        incidents = AlertEvent.objects.select_related("rule", "server").filter(is_resolved=False).order_by("-created_at")
        context.update(
            {
                "incidents": incidents,
                "incident_count": incidents.count(),
                "evidence_count": AlertEmailLog.objects.count(),
                "monitor_count": ServerMonitorAssignment.objects.filter(is_enabled=True).count(),
                "active_menu": "incidents",
            }
        )
        context.update(sidebar_context())
        return context


class ComplianceView(PortalAccessMixin, PortalDataMixin, TemplateView):
    template_name = "inventory/compliance.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        rows = self.server_rows()
        summary = self.summarize(rows)
        controls = ComplianceEvidence.controls(rows, summary)
        context.update(
            {
                "frameworks": ComplianceEvidence.frameworks(controls),
                "controls": controls,
                "evidence_summary": ComplianceEvidence.evidence_summary(rows),
                "audit_rows": ComplianceEvidence.audit_rows(rows),
                "gaps": ComplianceEvidence.gaps(rows),
                "summary": summary,
                "active_menu": "compliance",
            }
        )
        context.update(sidebar_context())
        return context


class ComplianceReportDownloadView(PortalAccessMixin, PortalDataMixin, TemplateView):
    def get(self, request, *args, **kwargs):
        rows = self.server_rows()
        response = HttpResponse(content_type="text/csv; charset=utf-8")
        timestamp = timezone.localtime().strftime("%Y%m%d-%H%M")
        response["Content-Disposition"] = f'attachment; filename="reporte-cumplimiento-{timestamp}.csv"'
        response.write("\ufeff")
        writer = csv.writer(response, delimiter=";")
        writer.writerow(
            [
                "Activo",
                "IP",
                "Grupo",
                "Ambiente",
                "Responsable",
                "Estado",
                "Sistema operativo",
                "Version agente",
                "Cobertura CMDB",
                "Puntaje seguridad",
                "Alertas activas",
                "Servicios",
                "Procesos",
                "Puertos",
                "Evidencia disponible",
                "Brechas",
                "Ultimo monitoreo",
            ]
        )
        for row in ComplianceEvidence.audit_rows(rows):
            writer.writerow(
                [
                    row["hostname"],
                    row["ip"],
                    row["group"],
                    row["environment"],
                    row["owner"],
                    row["status"],
                    row["os"],
                    row["agent_version"],
                    row["coverage_score"],
                    row["security_score"],
                    row["alert_count"],
                    row["service_count"],
                    row["process_count"],
                    row["port_count"],
                    row["evidence"],
                    row["gaps"],
                    row["last_seen"],
                ]
            )
        return response


class ComplianceEvidence:
    frameworks_catalog = [
        {
            "name": "Ley 21.663",
            "description": "Continuidad operacional, trazabilidad de incidentes, evidencia y reportabilidad.",
            "control_keys": ["asset_inventory", "continuous_monitoring", "incident_traceability", "reporting"],
        },
        {
            "name": "ISO 27001",
            "description": "Gestion de activos, controles operacionales, eventos, mejora continua y evidencias.",
            "control_keys": ["asset_inventory", "security_baseline", "incident_traceability", "evidence"],
        },
        {
            "name": "CIS Controls",
            "description": "Inventario, configuracion segura, vulnerabilidades, logs, puertos y monitoreo continuo.",
            "control_keys": ["asset_inventory", "security_baseline", "runtime_visibility", "continuous_monitoring"],
        },
        {
            "name": "CSIRT",
            "description": "Antecedentes tecnicos para comunicar incidentes relevantes cuando corresponda.",
            "control_keys": ["incident_traceability", "evidence", "reporting"],
        },
    ]

    @classmethod
    def frameworks(cls, controls):
        control_map = {control["key"]: control for control in controls}
        frameworks = []
        for framework in cls.frameworks_catalog:
            related = [control_map[key] for key in framework["control_keys"] if key in control_map]
            score = int(sum(item["score"] for item in related) / len(related)) if related else 0
            frameworks.append({**framework, "score": score, "controls": related})
        return frameworks

    @staticmethod
    def controls(rows, summary):
        total = len(rows) or 1
        with_inventory = sum(1 for row in rows if row["inventory"])
        with_runtime = sum(1 for row in rows if row["runtime"])
        good_security = sum(1 for row in rows if row["security"]["score"] >= 75)
        with_alerts = AlertEvent.objects.count()
        email_logs = AlertEmailLog.objects.count()
        monitor_count = ServerMonitorAssignment.objects.filter(is_enabled=True).count()
        active_critical = AlertEvent.objects.filter(is_resolved=False, rule__priority=AlertRule.PRIORITY_CRITICAL).count()
        return [
            {
                "key": "asset_inventory",
                "name": "Inventario y CMDB",
                "domain": "Activos",
                "score": int(with_inventory / total * 100),
                "detail": f"{with_inventory}/{len(rows)} activos con inventario tecnico",
                "evidence": "Inventario del agente, grupo, IP, sistema operativo, hardware y relaciones.",
            },
            {
                "key": "continuous_monitoring",
                "name": "Monitoreo continuo",
                "domain": "Continuidad",
                "score": int(with_runtime / total * 100),
                "detail": f"{with_runtime}/{len(rows)} activos con runtime",
                "evidence": "Metricas, disponibilidad, servicios, procesos, puertos y ultimos reportes.",
            },
            {
                "key": "security_baseline",
                "name": "Linea base de ciberseguridad",
                "domain": "Ciberseguridad",
                "score": int(good_security / total * 100),
                "detail": f"{good_security}/{len(rows)} activos con puntaje de seguridad >= 75",
                "evidence": "Firewall, hardening del sistema, actualizaciones, trazabilidad e inventario.",
            },
            {
                "key": "runtime_visibility",
                "name": "Visibilidad de exposicion",
                "domain": "Superficie",
                "score": min(100, int((sum(row["port_count"] > 0 for row in rows) + sum(row["service_count"] > 0 for row in rows)) / (total * 2) * 100)),
                "detail": "Servicios y puertos detectados por agente",
                "evidence": "Puertos abiertos, servicios activos y procesos principales.",
            },
            {
                "key": "incident_traceability",
                "name": "Incidentes y trazabilidad",
                "domain": "Operacion",
                "score": max(40, 100 - min(60, active_critical * 20)),
                "detail": f"{with_alerts} eventos registrados, {active_critical} criticos activos",
                "evidence": "Eventos de alerta, fecha de inicio, servidor afectado, severidad y estado.",
            },
            {
                "key": "evidence",
                "name": "Evidencias de notificacion",
                "domain": "Auditoria",
                "score": 100 if email_logs else 35,
                "detail": f"{email_logs} registros de correo y evidencia operacional",
                "evidence": "Historial de notificaciones, destinatarios, asunto, estado y errores.",
            },
            {
                "key": "reporting",
                "name": "Reportabilidad y umbrales",
                "domain": "Gobierno",
                "score": min(100, monitor_count * 10),
                "detail": f"{monitor_count} monitores asignados",
                "evidence": "Reglas, umbrales, destinatarios, frecuencia e historial de alertas.",
            },
        ]

    @staticmethod
    def evidence_summary(rows):
        return {
            "assets": len(rows),
            "inventory": sum(1 for row in rows if row["inventory"]),
            "runtime": sum(1 for row in rows if row["runtime"]),
            "alerts": AlertEvent.objects.count(),
            "notifications": AlertEmailLog.objects.count(),
            "assignments": ServerMonitorAssignment.objects.filter(is_enabled=True).count(),
        }

    @staticmethod
    def audit_rows(rows):
        audit_rows = []
        for row in rows:
            server = row["server"]
            last_seen = timezone.localtime(server.last_seen).strftime("%Y-%m-%d %H:%M:%S") if server.last_seen else "-"
            evidence = []
            if row["inventory"]:
                evidence.append("Inventario")
            if row["runtime"]:
                evidence.append("Runtime")
            if row["sample"]:
                evidence.append("Metricas")
            if row["alerts"]:
                evidence.append("Alertas")
            if row["interface_count"]:
                evidence.append("Red")
            audit_rows.append(
                {
                    "hostname": server.hostname,
                    "ip": row["ip_label"],
                    "group": server.group.name if server.group else "Sin grupo",
                    "environment": server.environment or "Sin ambiente",
                    "owner": server.owner or "Sin responsable",
                    "status": "En linea" if row["online"] else "Fuera de linea",
                    "os": row["os_label"],
                    "agent_version": row["agent_version"],
                    "coverage_score": row["coverage_score"],
                    "security_score": row["security"]["score"],
                    "alert_count": len(row["alerts"]),
                    "service_count": row["service_count"],
                    "process_count": row["process_count"],
                    "port_count": row["port_count"],
                    "evidence": ", ".join(evidence) if evidence else "Sin evidencia",
                    "gaps": ", ".join(row["missing_inventory"]) if row["missing_inventory"] else "Sin brechas",
                    "last_seen": last_seen,
                }
            )
        return sorted(audit_rows, key=lambda item: (item["coverage_score"], item["hostname"]))[:50]

    @staticmethod
    def gaps(rows):
        gaps = []
        for row in rows:
            if row["missing_inventory"] or row["security"]["score"] < 75 or row["alerts"]:
                gaps.append(
                    {
                        "server": row["server"],
                        "coverage": row["coverage_score"],
                        "security": row["security"]["score"],
                        "alerts": len(row["alerts"]),
                        "missing": row["missing_inventory"],
                    }
                )
        return sorted(gaps, key=lambda item: (item["coverage"], item["security"]))[:10]


class ReportsView(PortalAccessMixin, PortalDataMixin, TemplateView):
    template_name = "inventory/reports.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        rows = self.server_rows()
        context.update(
            {
                "summary": self.summarize(rows),
                "technical_rows": rows,
                "executive_items": self.executive_items(rows),
                "csirt_items": AlertEvent.objects.select_related("rule", "server").filter(rule__priority=AlertRule.PRIORITY_CRITICAL).order_by("-created_at")[:10],
                "active_menu": "reports",
            }
        )
        context.update(sidebar_context())
        return context

    @staticmethod
    def executive_items(rows):
        return sorted(rows, key=lambda item: item["risk_score"], reverse=True)[:10]
