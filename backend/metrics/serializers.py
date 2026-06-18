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
