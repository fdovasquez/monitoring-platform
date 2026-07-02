from django.contrib import admin

from .models import CentralReportQueue, MetricSample


@admin.register(MetricSample)
class MetricSampleAdmin(admin.ModelAdmin):
    list_display = ("server", "timestamp", "cpu_percent", "memory_percent", "disk_percent", "uptime_seconds")
    list_filter = ("server",)
    search_fields = ("server__hostname",)
    readonly_fields = ("created_at", "payload")
    date_hierarchy = "timestamp"


@admin.register(CentralReportQueue)
class CentralReportQueueAdmin(admin.ModelAdmin):
    list_display = ("id", "status", "attempts", "created_at", "sent_at")
    list_filter = ("status",)
    readonly_fields = ("payload", "last_error", "created_at", "updated_at", "sent_at")
    date_hierarchy = "created_at"
