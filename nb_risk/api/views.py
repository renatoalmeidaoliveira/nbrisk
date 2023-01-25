from netbox.api.viewsets import NetBoxModelViewSet

from .. import models
from . import serializers

# ThreatSource ViewSets

class ThreatSourceViewSet(NetBoxModelViewSet):
    queryset = models.ThreatSource.objects.all()
    serializer_class = serializers.ThreatSourceSerializer
    
# ThreatEvent ViewSets

class ThreatEventViewSet(NetBoxModelViewSet):
    queryset = models.ThreatEvent.objects.all()
    serializer_class = serializers.ThreatEventSerializer

# Vulnerability ViewSets

class VulnerabilityViewSet(NetBoxModelViewSet):
    queryset = models.Vulnerability.objects.all()
    serializer_class = serializers.VulnerabilitySerializer
    
# VulnerabilityAssignment ViewSets

class VulnerabilityAssignmentViewSet(NetBoxModelViewSet):
    queryset = models.VulnerabilityAssignment.objects.all()
    serializer_class = serializers.VulnerabilityAssignmentSerializer

# Risk ViewSets

class RiskViewSet(NetBoxModelViewSet):
    queryset = models.Risk.objects.all()
    serializer_class = serializers.RiskSerializer