from datetime import timedelta

from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.db.models import Count, OuterRef, Q, Subquery
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
            rows.append(
                {
                    "server": server,
                    "sample": sample,
                    "online": bool(server.last_seen and server.last_seen >= now - self.online_window),
                    "alerts": alerts,
                    "alert_level": self.alert_level(alerts),
                    "security": security,
                    "risk_score": self.risk_score(server, sample, alerts, security),
                    "inventory": getattr(server, "inventory", None),
                    "runtime": getattr(server, "runtime_snapshot", None),
                }
            )
        return rows

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
                "groups": self.cmdb_groups(rows),
                "relationships": self.relationships(rows),
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

    frameworks = [
        ("Ley 21.663", "Continuidad, gestion de incidentes, evidencia y reporte cuando corresponda."),
        ("ISO 27001", "Controles de seguridad, activos, eventos, trazabilidad y mejora continua."),
        ("CIS Controls", "Inventario, configuracion segura, vulnerabilidades, logs y monitoreo continuo."),
        ("CSIRT", "Preparacion de evidencia tecnica para comunicaciones de incidentes relevantes."),
    ]

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        rows = self.server_rows()
        summary = self.summarize(rows)
        context.update(
            {
                "frameworks": self.framework_status(summary, rows),
                "controls": self.control_status(rows),
                "summary": summary,
                "active_menu": "compliance",
            }
        )
        context.update(sidebar_context())
        return context

    def framework_status(self, summary, rows):
        controls = self.control_status(rows)
        control_score = int(sum(item["score"] for item in controls) / len(controls)) if controls else 0
        return [
            {"name": name, "description": description, "score": min(100, (control_score + summary["compliance"]) // 2)}
            for name, description in self.frameworks
        ]

    @staticmethod
    def control_status(rows):
        total = len(rows) or 1
        with_inventory = sum(1 for row in rows if row["inventory"])
        with_alerts = AlertEvent.objects.count()
        with_monitors = ServerMonitorAssignment.objects.filter(is_enabled=True).count()
        with_runtime = sum(1 for row in rows if row["runtime"])
        good_security = sum(1 for row in rows if row["security"]["score"] >= 75)
        return [
            {"name": "Inventario y CMDB", "score": int(with_inventory / total * 100), "detail": f"{with_inventory}/{len(rows)} activos con inventario"},
            {"name": "Monitoreo continuo", "score": int(with_runtime / total * 100), "detail": f"{with_runtime}/{len(rows)} activos con runtime"},
            {"name": "Ciberseguridad", "score": int(good_security / total * 100), "detail": f"{good_security}/{len(rows)} activos con puntaje >= 75"},
            {"name": "Incidentes y evidencia", "score": 100 if with_alerts else 40, "detail": f"{with_alerts} eventos registrados"},
            {"name": "Umbrales y responsables", "score": min(100, with_monitors * 10), "detail": f"{with_monitors} monitores asignados"},
        ]


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
