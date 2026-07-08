from django.db import transaction
from django.utils import timezone
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from inventory.models import AgentToken, Server, ServerInventory, ServerRuntimeSnapshot
from alerts.services import evaluate_metric_sample

from .models import MetricSample
from .serializers import MetricIngestSerializer, RhapsodyIngestSerializer


def bearer_token(request):
    header = request.headers.get("Authorization", "")
    prefix = "Bearer "
    if not header.startswith(prefix):
        return None
    return header[len(prefix) :].strip()


class MetricIngestView(APIView):
    authentication_classes = []
    permission_classes = []

    def post(self, request):
        token_value = bearer_token(request)
        if not token_value:
            return Response({"detail": "Missing bearer token."}, status=status.HTTP_401_UNAUTHORIZED)

        try:
            agent_token = AgentToken.objects.select_related("server").get(token=token_value, is_active=True)
        except AgentToken.DoesNotExist:
            return Response({"detail": "Invalid token."}, status=status.HTTP_403_FORBIDDEN)

        serializer = MetricIngestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        metrics = data.get("metrics", {})

        disk_percent = metrics.get("disk_root_percent")
        if disk_percent is None:
            disk_percent = metrics.get("disk_c_percent")

        with transaction.atomic():
            server = resolve_server_for_token(agent_token, data)

            agent_token.last_used_at = timezone.now()
            agent_token.save(update_fields=["last_used_at"])

            sample = MetricSample.objects.create(
                server=server,
                timestamp=data["timestamp"],
                agent_version=data.get("agent_version", ""),
                cpu_percent=metrics.get("cpu_percent"),
                memory_percent=metrics.get("memory_percent"),
                disk_percent=disk_percent,
                uptime_seconds=metrics.get("uptime_seconds"),
                payload=request.data,
            )
            update_inventory(server, data.get("inventory", {}), data["timestamp"])
            update_runtime_snapshot(
                server,
                data.get("services", []),
                data.get("processes", []),
                data.get("ports", []),
                data["timestamp"],
            )

        evaluate_metric_sample(sample)
        return Response({"status": "ok", "sample_id": sample.id}, status=status.HTTP_201_CREATED)


class RhapsodyIngestView(APIView):
    authentication_classes = []
    permission_classes = []

    def post(self, request):
        token_value = bearer_token(request)
        if not token_value:
            return Response({"detail": "Missing bearer token."}, status=status.HTTP_401_UNAUTHORIZED)

        try:
            agent_token = AgentToken.objects.select_related("server").get(token=token_value, is_active=True)
        except AgentToken.DoesNotExist:
            return Response({"detail": "Invalid token."}, status=status.HTTP_403_FORBIDDEN)

        serializer = RhapsodyIngestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        application_payload = dict(request.data)

        with transaction.atomic():
            server = agent_token.server
            hostname = clean_text(data.get("hostname"))
            if hostname and server.hostname.startswith("pendiente-"):
                server.hostname = hostname
                if server.name == "Agente pendiente de registro":
                    server.name = hostname
                server.save(update_fields=["hostname", "name", "updated_at"])

            agent_token.last_used_at = timezone.now()
            agent_token.save(update_fields=["last_used_at"])
            update_application_snapshot(server, "rhapsody", application_payload, data["timestamp"])

        return Response({"status": "ok", "application": "rhapsody"}, status=status.HTTP_201_CREATED)


def resolve_server_for_token(agent_token, data):
    server = agent_token.server
    hostname = clean_text(data["hostname"])
    inventory = data.get("inventory", {}) if isinstance(data.get("inventory", {}), dict) else {}
    primary_ip = clean_ip(inventory.get("primary_ip"))
    os_name = clean_text(inventory.get("os_name")).lower()
    os_type = Server.OS_WINDOWS if "windows" in os_name else (Server.OS_LINUX if os_name else server.os_type)
    is_pending = server.hostname.startswith("pendiente-")

    existing = Server.objects.filter(hostname=hostname).exclude(pk=server.pk).first()
    if is_pending and existing:
        AgentToken.objects.filter(server=existing).exclude(pk=agent_token.pk).delete()
        previous_server = server
        agent_token.server = existing
        agent_token.save(update_fields=["server"])
        server = existing
        previous_server.delete()

    server.hostname = hostname
    if is_pending and server.name == "Agente pendiente de registro":
        server.name = hostname
    if primary_ip:
        server.ip_address = primary_ip
    server.os_type = os_type
    server.last_seen = timezone.now()
    server.is_active = True
    server.save(update_fields=["hostname", "name", "ip_address", "os_type", "last_seen", "is_active", "updated_at"])
    return server


def clean_text(value, max_length=255):
    if value is None:
        return ""
    return str(value).strip()[:max_length]


def clean_ip(value):
    value = clean_text(value)
    return value or None


def update_inventory(server, inventory, collected_at):
    if not isinstance(inventory, dict) or not inventory:
        return
    defaults = {
        "fqdn": clean_text(inventory.get("fqdn")),
        "os_name": clean_text(inventory.get("os_name")),
        "os_version": clean_text(inventory.get("os_version")),
        "kernel": clean_text(inventory.get("kernel")),
        "architecture": clean_text(inventory.get("architecture")),
        "serial_number": clean_text(inventory.get("serial_number")),
        "model": clean_text(inventory.get("model")),
        "manufacturer": clean_text(inventory.get("manufacturer")),
        "domain": clean_text(inventory.get("domain")),
        "logged_user": clean_text(inventory.get("logged_user")),
        "primary_ip": clean_ip(inventory.get("primary_ip")),
        "gateway": clean_text(inventory.get("gateway")),
        "dns_servers": inventory.get("dns_servers") if isinstance(inventory.get("dns_servers"), list) else [],
        "mac_addresses": inventory.get("mac_addresses") if isinstance(inventory.get("mac_addresses"), list) else [],
        "interfaces": inventory.get("interfaces") if isinstance(inventory.get("interfaces"), list) else [],
        "timezone": clean_text(inventory.get("timezone")),
        "raw_data": inventory,
        "collected_at": collected_at,
    }
    ServerInventory.objects.update_or_create(server=server, defaults=defaults)


def clean_list(value):
    return value if isinstance(value, list) else []


def update_runtime_snapshot(server, services, processes, ports, collected_at):
    services = clean_list(services)
    processes = clean_list(processes)
    ports = clean_list(ports)
    if not services and not processes and not ports:
        return
    defaults = {
        "services": services[:250],
        "processes": processes[:100],
        "ports": ports[:250],
        "raw_data": {
            "services": services,
            "processes": processes,
            "ports": ports,
        },
        "collected_at": collected_at,
    }
    ServerRuntimeSnapshot.objects.update_or_create(server=server, defaults=defaults)


def update_application_snapshot(server, application_name, application_data, collected_at):
    runtime, _ = ServerRuntimeSnapshot.objects.get_or_create(server=server)
    raw_data = runtime.raw_data if isinstance(runtime.raw_data, dict) else {}
    applications = raw_data.get("applications") if isinstance(raw_data.get("applications"), dict) else {}
    applications[application_name] = application_data
    raw_data["applications"] = applications
    runtime.raw_data = raw_data
    runtime.collected_at = collected_at
    runtime.save(update_fields=["raw_data", "collected_at", "updated_at"])

