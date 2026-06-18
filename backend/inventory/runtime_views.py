from django.contrib.auth.mixins import LoginRequiredMixin
from django.shortcuts import get_object_or_404
from django.views.generic import TemplateView

from .models import Server, ServerRuntimeSnapshot
from .views import sidebar_context


class DeviceRuntimeView(LoginRequiredMixin, TemplateView):
    template_name = "inventory/device_runtime.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        server = get_object_or_404(Server.objects.select_related("group"), id=kwargs["pk"])
        runtime = self.runtime_snapshot(server)
        context.update(
            {
                "server": server,
                "runtime": runtime,
            }
        )
        context.update(sidebar_context())
        return context

    @staticmethod
    def runtime_snapshot(server):
        try:
            runtime = server.runtime_snapshot
        except ServerRuntimeSnapshot.DoesNotExist:
            return None

        services = runtime.services or []
        processes = runtime.processes or []
        ports = runtime.ports or []
        stopped_services = [
            service
            for service in services
            if str(service.get("state", "")).lower() not in ["active", "running"]
        ]
        return {
            "record": runtime,
            "services": services[:80],
            "stopped_services": stopped_services[:30],
            "processes": processes[:40],
            "ports": ports[:120],
            "service_count": len(services),
            "process_count": len(processes),
            "port_count": len(ports),
            "stopped_count": len(stopped_services),
        }
