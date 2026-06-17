from django.contrib import admin

from .models import AlertEmailLog, AlertEvent, AlertRule, SmtpSettings


@admin.register(SmtpSettings)
class SmtpSettingsAdmin(admin.ModelAdmin):
    list_display = ("host", "port", "from_email", "security", "require_auth", "updated_at")
    readonly_fields = ("encrypted_password", "updated_at")


@admin.register(AlertRule)
class AlertRuleAdmin(admin.ModelAdmin):
    list_display = ("name", "event_type", "threshold", "priority", "is_active", "min_interval_minutes", "last_notified_at")
    list_filter = ("event_type", "priority", "is_active")
    search_fields = ("name",)


@admin.register(AlertEvent)
class AlertEventAdmin(admin.ModelAdmin):
    list_display = ("rule", "server", "value", "is_resolved", "created_at", "resolved_at")
    list_filter = ("is_resolved", "rule")
    search_fields = ("server__hostname", "message")
    readonly_fields = ("created_at",)


@admin.register(AlertEmailLog)
class AlertEmailLogAdmin(admin.ModelAdmin):
    list_display = ("created_at", "status", "alert_type", "severity", "server", "subject")
    list_filter = ("status", "severity", "alert_type")
    search_fields = ("server__hostname", "recipients", "subject", "message", "error_message")
    readonly_fields = ("created_at",)
