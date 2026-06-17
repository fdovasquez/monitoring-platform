import secrets

from django.db import models


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
