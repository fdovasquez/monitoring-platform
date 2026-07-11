from rest_framework import serializers


class SatelliteReportSerializer(serializers.Serializer):
    satellite_id = serializers.CharField(max_length=120)
    satellite_name = serializers.CharField(max_length=160)
    timestamp = serializers.DateTimeField()
    hostname = serializers.CharField(max_length=255, required=False, allow_blank=True)
    site_name = serializers.CharField(max_length=160, required=False, allow_blank=True)
    agents = serializers.ListField(required=False)
    metrics = serializers.ListField(required=False)
    alerts = serializers.ListField(required=False)
    status = serializers.DictField(required=False)
