import secrets
import base64
import hashlib

from cryptography.fernet import Fernet
from django.conf import settings
from django.contrib.auth.models import User
from django.db import models


class DeviceGroup(models.Model):
    name = models.CharField(max_length=120, unique=True)
    description = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name


def profile_photo_path(instance, filename):
    extension = filename.rsplit(".", 1)[-1].lower() if "." in filename else "jpg"
    return f"profiles/user-{instance.user_id}/avatar.{extension}"


def site_logo_path(instance, filename):
    extension = filename.rsplit(".", 1)[-1].lower() if "." in filename else "png"
    return f"site/logo.{extension}"


class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="profile")
    phone = models.CharField(max_length=40, blank=True)
    position = models.CharField(max_length=120, blank=True)
    photo = models.ImageField(upload_to=profile_photo_path, blank=True, null=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["user__username"]

    def __str__(self):
        return f"Perfil {self.user.username}"


class SiteSettings(models.Model):
    site_name = models.CharField(max_length=120, default="AGFA HealthCare")
    subtitle = models.CharField(max_length=160, default="Monitor de servidores")
    logo = models.ImageField(upload_to=site_logo_path, blank=True, null=True)
    logo_width = models.PositiveIntegerField(default=126)
    logo_height = models.PositiveIntegerField(default=38)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Configuracion del sitio"
        verbose_name_plural = "Configuracion del sitio"

    def save(self, *args, **kwargs):
        self.pk = 1
        return super().save(*args, **kwargs)

    @classmethod
    def load(cls):
        settings, _ = cls.objects.get_or_create(pk=1)
        return settings

    def __str__(self):
        return self.site_name


class TlsCertificate(models.Model):
    """Single TLS certificate stored by the platform for the Nginx export command."""

    domain = models.CharField(max_length=255, blank=True)
    certificate_pem = models.TextField(blank=True)
    encrypted_private_key = models.TextField(blank=True)
    certificate_filename = models.CharField(max_length=255, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Certificado HTTPS"
        verbose_name_plural = "Certificados HTTPS"

    def save(self, *args, **kwargs):
        self.pk = 1
        return super().save(*args, **kwargs)

    @classmethod
    def load(cls):
        certificate, _ = cls.objects.get_or_create(pk=1)
        return certificate

    @property
    def is_configured(self):
        return bool(self.certificate_pem and self.encrypted_private_key)

    def set_private_key(self, private_key):
        self.encrypted_private_key = credential_cipher().encrypt(private_key.encode("utf-8")).decode("utf-8")

    def get_private_key(self):
        if not self.encrypted_private_key:
            return ""
        return credential_cipher().decrypt(self.encrypted_private_key.encode("utf-8")).decode("utf-8")

    def clear(self):
        self.domain = ""
        self.certificate_pem = ""
        self.encrypted_private_key = ""
        self.certificate_filename = ""

    def __str__(self):
        return self.domain or "Certificado HTTPS"


class Server(models.Model):
    OS_LINUX = "linux"
    OS_WINDOWS = "windows"
    OS_OTHER = "other"
    OS_CHOICES = [
        (OS_LINUX, "Linux"),
        (OS_WINDOWS, "Windows"),
        (OS_OTHER, "Otro"),
    ]

    hostname = models.CharField(max_length=255, unique=True)
    name = models.CharField(max_length=255, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    group = models.ForeignKey(DeviceGroup, on_delete=models.SET_NULL, null=True, blank=True, related_name="servers")
    os_type = models.CharField(max_length=20, choices=OS_CHOICES, default=OS_LINUX)
    environment = models.CharField(max_length=100, blank=True)
    owner = models.CharField(max_length=255, blank=True)
    is_active = models.BooleanField(default=True)
    last_seen = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["hostname"]

    def __str__(self):
        return self.name or self.hostname


class ServerInventory(models.Model):
    server = models.OneToOneField(Server, on_delete=models.CASCADE, related_name="inventory")
    fqdn = models.CharField(max_length=255, blank=True)
    os_name = models.CharField(max_length=255, blank=True)
    os_version = models.CharField(max_length=255, blank=True)
    kernel = models.CharField(max_length=255, blank=True)
    architecture = models.CharField(max_length=120, blank=True)
    serial_number = models.CharField(max_length=255, blank=True)
    model = models.CharField(max_length=255, blank=True)
    manufacturer = models.CharField(max_length=255, blank=True)
    domain = models.CharField(max_length=255, blank=True)
    logged_user = models.CharField(max_length=255, blank=True)
    primary_ip = models.GenericIPAddressField(null=True, blank=True)
    gateway = models.CharField(max_length=255, blank=True)
    dns_servers = models.JSONField(default=list, blank=True)
    mac_addresses = models.JSONField(default=list, blank=True)
    interfaces = models.JSONField(default=list, blank=True)
    timezone = models.CharField(max_length=120, blank=True)
    raw_data = models.JSONField(default=dict, blank=True)
    collected_at = models.DateTimeField(null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["server__hostname"]

    def __str__(self):
        return f"Inventario {self.server.hostname}"


class ServerRuntimeSnapshot(models.Model):
    server = models.OneToOneField(Server, on_delete=models.CASCADE, related_name="runtime_snapshot")
    services = models.JSONField(default=list, blank=True)
    processes = models.JSONField(default=list, blank=True)
    ports = models.JSONField(default=list, blank=True)
    raw_data = models.JSONField(default=dict, blank=True)
    collected_at = models.DateTimeField(null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["server__hostname"]

    def __str__(self):
        return f"Runtime {self.server.hostname}"


def credential_cipher():
    digest = hashlib.sha256(settings.SECRET_KEY.encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


class MachineCredential(models.Model):
    AUTH_PASSWORD = "password"
    AUTH_CHOICES = [
        (AUTH_PASSWORD, "Clave SSH"),
    ]

    server = models.ForeignKey(Server, on_delete=models.CASCADE, related_name="credentials")
    label = models.CharField(max_length=120)
    username = models.CharField(max_length=120)
    port = models.PositiveIntegerField(default=22)
    auth_method = models.CharField(max_length=20, choices=AUTH_CHOICES, default=AUTH_PASSWORD)
    encrypted_secret = models.TextField(blank=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_used_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["label", "username"]
        unique_together = ("server", "label")

    def __str__(self):
        return f"{self.label} ({self.username})"

    def set_secret(self, secret):
        self.encrypted_secret = credential_cipher().encrypt(secret.encode("utf-8")).decode("utf-8")

    def get_secret(self):
        if not self.encrypted_secret:
            return ""
        return credential_cipher().decrypt(self.encrypted_secret.encode("utf-8")).decode("utf-8")


def generate_agent_token():
    return secrets.token_urlsafe(48)


class AgentToken(models.Model):
    server = models.OneToOneField(Server, on_delete=models.CASCADE, related_name="agent_token")
    token = models.CharField(max_length=128, unique=True, default=generate_agent_token)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["server__hostname"]

    def __str__(self):
        return f"Token {self.server.hostname}"
