from django.contrib import admin

from .models import MetricSample


@admin.register(MetricSample)
class MetricSampleAdmin(admin.ModelAdmin):
    list_display = ("server", "timestamp", "cpu_percent", "memory_percent", "disk_percent", "uptime_seconds")
    list_filter = ("server",)
    search_fields = ("server__hostname",)
    readonly_fields = ("created_at", "payload")
    date_hierarchy = "timestamp"
