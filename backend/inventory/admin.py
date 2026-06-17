from django.contrib import admin

from .models import AgentToken, Server


@admin.register(Server)
class ServerAdmin(admin.ModelAdmin):
    list_display = ("hostname", "ip_address", "os_type", "environment", "is_active", "last_seen")
    list_filter = ("os_type", "environment", "is_active")
    search_fields = ("hostname", "name", "ip_address", "owner")
    readonly_fields = ("created_at", "updated_at", "last_seen")


@admin.register(AgentToken)
class AgentTokenAdmin(admin.ModelAdmin):
    list_display = ("server", "is_active", "created_at", "last_used_at")
    list_filter = ("is_active",)
    search_fields = ("server__hostname", "token")
    readonly_fields = ("created_at", "last_used_at")
