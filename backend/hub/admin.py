from django.contrib import admin

from .models import Satellite, SatelliteAlert, SatelliteReport, SatelliteServerSnapshot


@admin.register(Satellite)
class SatelliteAdmin(admin.ModelAdmin):
    list_display = ("name", "satellite_id", "status", "servers_total", "alerts_unresolved", "last_report_at")
    search_fields = ("name", "satellite_id", "hostname", "site_name")
    list_filter = ("status",)


@admin.register(SatelliteReport)
class SatelliteReportAdmin(admin.ModelAdmin):
    list_display = ("satellite", "report_timestamp", "agents_count", "metrics_count", "alerts_count", "received_at")
    list_filter = ("satellite",)
    search_fields = ("satellite__name", "source_hostname", "site_name")


@admin.register(SatelliteServerSnapshot)
class SatelliteServerSnapshotAdmin(admin.ModelAdmin):
    list_display = ("hostname", "satellite", "ip_address", "group", "os_type", "agent_version", "last_seen")
    list_filter = ("satellite", "os_type", "group")
    search_fields = ("hostname", "name", "ip_address", "group")


@admin.register(SatelliteAlert)
class SatelliteAlertAdmin(admin.ModelAdmin):
    list_display = ("rule", "satellite", "server_hostname", "priority", "is_resolved", "source_created_at")
    list_filter = ("satellite", "priority", "is_resolved")
    search_fields = ("rule", "server_hostname", "message")
