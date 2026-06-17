from django.contrib import admin

from .models import AlertEvent, AlertRule


@admin.register(AlertRule)
class AlertRuleAdmin(admin.ModelAdmin):
    list_display = ("name", "metric", "threshold", "is_active", "created_at")
    list_filter = ("metric", "is_active")
    search_fields = ("name",)


@admin.register(AlertEvent)
class AlertEventAdmin(admin.ModelAdmin):
    list_display = ("rule", "server", "value", "is_resolved", "created_at", "resolved_at")
    list_filter = ("is_resolved", "rule")
    search_fields = ("server__hostname", "message")
    readonly_fields = ("created_at",)
