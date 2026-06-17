from django.db import transaction
from django.utils import timezone
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from inventory.models import AgentToken

from .models import MetricSample
from .serializers import MetricIngestSerializer


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
            server = agent_token.server
            server.hostname = data["hostname"]
            server.last_seen = timezone.now()
            server.save(update_fields=["hostname", "last_seen", "updated_at"])

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

        return Response({"status": "ok", "sample_id": sample.id}, status=status.HTTP_201_CREATED)
