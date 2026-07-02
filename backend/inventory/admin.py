from django.contrib import admin

from .models import (
    AgentToken,
    CentralMonitorSettings,
    DeviceGroup,
    MachineCredential,
    Server,
    ServerInventory,
    ServerRuntimeSnapshot,
    SiteSettings,
    UserProfile,
)


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


@admin.register(ServerInventory)
class ServerInventoryAdmin(admin.ModelAdmin):
    list_display = ("server", "os_name", "os_version", "architecture", "primary_ip", "collected_at", "updated_at")
    search_fields = ("server__hostname", "fqdn", "serial_number", "model", "manufacturer", "primary_ip")
    readonly_fields = ("raw_data", "updated_at")


@admin.register(ServerRuntimeSnapshot)
class ServerRuntimeSnapshotAdmin(admin.ModelAdmin):
    list_display = ("server", "service_count", "process_count", "port_count", "collected_at", "updated_at")
    search_fields = ("server__hostname",)
    readonly_fields = ("services", "processes", "ports", "raw_data", "updated_at")

    def service_count(self, obj):
        return len(obj.services or [])

    def process_count(self, obj):
        return len(obj.processes or [])

    def port_count(self, obj):
        return len(obj.ports or [])


@admin.register(AgentToken)
class AgentTokenAdmin(admin.ModelAdmin):
    list_display = ("server", "is_active", "created_at", "last_used_at")
    list_filter = ("is_active",)
    search_fields = ("server__hostname", "token")
    readonly_fields = ("created_at", "last_used_at")


@admin.register(MachineCredential)
class MachineCredentialAdmin(admin.ModelAdmin):
    list_display = ("server", "label", "username", "port", "is_active", "last_used_at")
    list_filter = ("is_active", "server__os_type")
    search_fields = ("server__hostname", "label", "username")
    readonly_fields = ("encrypted_secret", "created_at", "updated_at", "last_used_at")


@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ("user", "phone", "position", "updated_at")
    search_fields = ("user__username", "user__first_name", "user__last_name", "user__email", "phone", "position")
    readonly_fields = ("updated_at",)


@admin.register(SiteSettings)
class SiteSettingsAdmin(admin.ModelAdmin):
    list_display = ("site_name", "subtitle", "updated_at")
    readonly_fields = ("updated_at",)


@admin.register(CentralMonitorSettings)
class CentralMonitorSettingsAdmin(admin.ModelAdmin):
    list_display = ("satellite_id", "satellite_name", "central_api_url", "reporting_enabled", "updated_at")
    readonly_fields = ("encrypted_api_token", "updated_at")
