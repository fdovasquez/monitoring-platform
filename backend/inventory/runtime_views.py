from django.contrib.auth.mixins import LoginRequiredMixin
from django.shortcuts import get_object_or_404
from django.views.generic import TemplateView

from .models import Server, ServerRuntimeSnapshot
from .views import sidebar_context


class DeviceRuntimeView(LoginRequiredMixin, TemplateView):
    template_name = "inventory/device_runtime.html"
    section_options = {
        "services": {
            "title": "Servicios",
            "subtitle": "Estado de servicios reportados por el agente del servidor.",
            "empty": "Aun no hay servicios reportados por el agente.",
        },
        "processes": {
            "title": "Procesos",
            "subtitle": "Procesos principales reportados por consumo y usuario.",
            "empty": "Aun no hay procesos reportados por el agente.",
        },
        "ports": {
            "title": "Puertos",
            "subtitle": "Puertos abiertos y sockets en escucha detectados por el agente.",
            "empty": "Aun no hay puertos reportados por el agente.",
        },
    }

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        server = get_object_or_404(Server.objects.select_related("group"), id=kwargs["pk"])
        runtime = self.runtime_snapshot(server)
        active_section = kwargs.get("section") or "services"
        if active_section not in self.section_options:
            active_section = "services"
        context.update(
            {
                "server": server,
                "runtime": runtime,
                "active_section": active_section,
                "section_meta": self.section_options[active_section],
                "section_options": self.section_options,
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

        services = [
            {
                "name": service.get("name") or service.get("display_name") or "-",
                "state": service.get("state") or "-",
                "start_type": service.get("start_type") or service.get("sub_state") or "-",
                "description": service.get("description") or service.get("display_name") or "-",
            }
            for service in runtime.services or []
            if isinstance(service, dict)
        ]
        processes = [
            {
                "pid": process.get("pid") or "-",
                "name": process.get("name") or process.get("command") or "-",
                "cpu_percent": process.get("cpu_percent") or 0,
                "memory_mb": process.get("memory_mb") or 0,
                "username": process.get("username") or process.get("user") or "-",
                "path": process.get("path") or process.get("exe") or "-",
            }
            for process in runtime.processes or []
            if isinstance(process, dict)
        ]
        ports = [
            {
                "protocol": port.get("protocol") or "-",
                "local_address": port.get("local_address") or port.get("address") or "-",
                "local_port": port.get("local_port") or port.get("port") or "-",
                "status": port.get("status") or port.get("state") or "open",
                "pid": port.get("pid") or "-",
                "process": port.get("process") or port.get("process_name") or "-",
            }
            for port in runtime.ports or []
            if isinstance(port, dict)
        ]
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
