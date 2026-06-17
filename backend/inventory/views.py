from datetime import timedelta

from django.contrib.auth.mixins import LoginRequiredMixin
from django.db.models import Prefetch
from django.utils import timezone
from django.views.generic import TemplateView

from metrics.models import MetricSample

from .models import Server


class DeviceListView(LoginRequiredMixin, TemplateView):
    template_name = "inventory/device_list.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        latest_samples = MetricSample.objects.order_by("-timestamp")
        servers = (
            Server.objects.prefetch_related(Prefetch("metric_samples", queryset=latest_samples, to_attr="latest_samples"))
            .select_related("agent_token")
            .order_by("hostname")
        )
        now = timezone.now()
        devices = []

        for server in servers:
            sample = server.latest_samples[0] if server.latest_samples else None
            online = bool(server.last_seen and server.last_seen >= now - timedelta(minutes=5))
            devices.append(
                {
                    "server": server,
                    "sample": sample,
                    "online": online,
                    "security_score": self.security_score(sample),
                    "uptime": self.format_uptime(sample.uptime_seconds if sample else None),
                    "latency": self.synthetic_latency(server.id),
                }
            )

        context["devices"] = devices
        context["total_devices"] = len(devices)
        context["online_devices"] = sum(1 for device in devices if device["online"])
        context["offline_devices"] = sum(1 for device in devices if not device["online"])
        context["windows_devices"] = sum(1 for device in devices if device["server"].os_type == Server.OS_WINDOWS)
        context["linux_devices"] = sum(1 for device in devices if device["server"].os_type == Server.OS_LINUX)
        return context

    @staticmethod
    def security_score(sample):
        if not sample:
            return 0
        score = 100
        for value in (sample.cpu_percent, sample.memory_percent, sample.disk_percent):
            if value and value >= 90:
                score -= 20
            elif value and value >= 80:
                score -= 10
        return max(score, 0)

    @staticmethod
    def synthetic_latency(server_id):
        return 6 + (server_id % 9)

    @staticmethod
    def format_uptime(seconds):
        if not seconds:
            return "-"
        minutes = int(seconds // 60)
        days, minutes = divmod(minutes, 1440)
        hours, minutes = divmod(minutes, 60)
        if days:
            return f"{days}d {hours}h {minutes}m"
        if hours:
            return f"{hours}h {minutes}m"
        return f"{minutes}m"
