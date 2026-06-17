import secrets
import base64
import hashlib

from cryptography.fernet import Fernet
from django.conf import settings
from django.db import models


class DeviceGroup(models.Model):
    name = models.CharField(max_length=120, unique=True)
    description = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name


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
