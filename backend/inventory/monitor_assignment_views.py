from alerts.models import AlertRule, ServerMonitorAssignment

from django.contrib import messages
from django.shortcuts import get_object_or_404, redirect

from .models import Server
from .views import DeviceDetailView, user_can_manage_devices


class DeviceDetailWithMonitorsView(DeviceDetailView):
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["monitor_assignments"] = self.monitor_assignments(context["server"])
        return context

    def post(self, request, pk):
        server = get_object_or_404(Server, id=pk)
        if not user_can_manage_devices(request.user):
            messages.error(request, "No tienes permisos para modificar los monitores de este servidor.")
            return redirect("device-detail", pk=server.id)

        action = request.POST.get("action", "")
        rule_id = request.POST.get("rule_id")
        rule = AlertRule.objects.filter(id=rule_id, is_active=True).first()
        if not rule:
            messages.error(request, "No se encontro el monitor seleccionado.")
            return redirect("device-detail", pk=server.id)

        assignment, _ = ServerMonitorAssignment.objects.get_or_create(server=server, rule=rule)
        if action == "assign_monitor":
            assignment.is_enabled = True
            assignment.save(update_fields=["is_enabled", "updated_at"])
            messages.success(request, f"Monitor '{rule.name}' asignado al servidor.")
        elif action == "remove_monitor":
            assignment.delete()
            messages.success(request, f"Monitor '{rule.name}' removido del servidor.")
        elif action == "toggle_monitor":
            assignment.is_enabled = not assignment.is_enabled
            assignment.save(update_fields=["is_enabled", "updated_at"])
            state = "habilitado" if assignment.is_enabled else "deshabilitado"
            messages.success(request, f"Monitor '{rule.name}' {state}.")
        else:
            messages.error(request, "Accion de monitor no valida.")
        return redirect("device-detail", pk=server.id)

    @staticmethod
    def monitor_assignments(server):
        rules = list(AlertRule.objects.filter(is_active=True).order_by("name"))
        assignments = {
            assignment.rule_id: assignment
            for assignment in ServerMonitorAssignment.objects.select_related("rule").filter(server=server)
        }
        active = []
        available = []
        for rule in rules:
            item = {
                "rule": rule,
                "assignment": assignments.get(rule.id),
                "description": DeviceDetailWithMonitorsView.monitor_description(rule),
                "threshold": DeviceDetailWithMonitorsView.monitor_threshold(rule),
            }
            if item["assignment"]:
                active.append(item)
            else:
                available.append(item)
        return {
            "active": active,
            "available": available,
            "active_count": len(active),
            "available_count": len(available),
        }

    @staticmethod
    def monitor_description(rule):
        descriptions = {
            AlertRule.EVENT_OFFLINE: "Valida que el agente siga reportando dentro del tiempo definido.",
            AlertRule.EVENT_CPU: "Supervisa el uso de procesador contra el umbral configurado.",
            AlertRule.EVENT_MEMORY: "Supervisa el consumo de memoria RAM.",
            AlertRule.EVENT_DISK: "Controla el porcentaje de uso total de disco.",
            AlertRule.EVENT_FREE_SPACE: "Alerta cuando el espacio libre cae bajo el minimo definido.",
            AlertRule.EVENT_SERVICE_STOPPED: "Detecta servicios detenidos en el sistema operativo.",
            AlertRule.EVENT_CRITICAL_SERVICE: "Vigila servicios criticos configurados para la plataforma.",
            AlertRule.EVENT_REBOOT: "Detecta reinicios no esperados o cambios bruscos de uptime.",
            AlertRule.EVENT_BACKUP: "Permite alertar errores asociados a respaldos.",
            AlertRule.EVENT_DATABASE: "Permite alertar fallas de conexion con bases de datos.",
        }
        return descriptions.get(rule.event_type, "Monitor configurable para este servidor.")

    @staticmethod
    def monitor_threshold(rule):
        if rule.event_type in [AlertRule.EVENT_CPU, AlertRule.EVENT_MEMORY, AlertRule.EVENT_DISK]:
            return f"Mayor que {rule.threshold:g}%"
        if rule.event_type == AlertRule.EVENT_FREE_SPACE:
            return f"Menos de {rule.threshold:g}% libre"
        if rule.event_type == AlertRule.EVENT_OFFLINE:
            return f"Sin reporte por {rule.threshold:g} min"
        if rule.event_type == AlertRule.EVENT_REBOOT and rule.threshold:
            return f"{rule.threshold:g} dias"
        return f"{rule.threshold:g} vez"
