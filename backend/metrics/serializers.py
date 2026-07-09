from rest_framework import serializers


class MetricIngestSerializer(serializers.Serializer):
    hostname = serializers.CharField(max_length=255)
    agent_version = serializers.CharField(max_length=50, required=False, allow_blank=True)
    timestamp = serializers.DateTimeField()
    metrics = serializers.DictField()
    inventory = serializers.DictField(required=False)
    services = serializers.ListField(required=False)
    processes = serializers.ListField(required=False)
    ports = serializers.ListField(required=False)


class RhapsodyIngestSerializer(serializers.Serializer):
    hostname = serializers.CharField(max_length=255, required=False, allow_blank=True)
    fqdn = serializers.CharField(max_length=255, required=False, allow_blank=True)
    agent_version = serializers.CharField(max_length=50, required=False, allow_blank=True)
    timestamp = serializers.DateTimeField()
    status = serializers.CharField(max_length=40)
    summary = serializers.CharField(required=False, allow_blank=True)
    services = serializers.ListField(required=False)
    processes = serializers.ListField(required=False)
    ports = serializers.ListField(required=False)
    log_findings = serializers.ListField(required=False)
    details = serializers.DictField(required=False)
