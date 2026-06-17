from django.contrib import admin

from .models import AgentToken, DeviceGroup, Server


@admin.register(DeviceGroup)
class DeviceGroupAdmin(admin.ModelAdmin):
    list_display = ("name", "created_at")
    search_fields = ("name", "description")
    readonly_fields = ("created_at",)


@admin.register(Server)
class ServerAdmin(admin.ModelAdmin):
    list_display = ("hostname", "ip_address", "group", "os_type", "environment", "is_active", "last_seen")
    list_filter = ("group", "os_type", "environment", "is_active")
    search_fields = ("hostname", "name", "ip_address", "owner")
    readonly_fields = ("created_at", "updated_at", "last_seen")


@admin.register(AgentToken)
class AgentTokenAdmin(admin.ModelAdmin):
    list_display = ("server", "is_active", "created_at", "last_used_at")
    list_filter = ("is_active",)
    search_fields = ("server__hostname", "token")
    readonly_fields = ("created_at", "last_used_at")
