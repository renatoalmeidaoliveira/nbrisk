from netbox.api.viewsets import NetBoxModelViewSet

from .. import models
from . import serializers

# ThreatSource ViewSets

class ThreatSourceViewSet(NetBoxModelViewSet):
    queryset = models.ThreatSource.objects.all().order_by('name')
    serializer_class = serializers.ThreatSourceSerializer

# ThreatEvent ViewSets

class ThreatEventViewSet(NetBoxModelViewSet):
    queryset = models.ThreatEvent.objects.all().order_by('name')
    serializer_class = serializers.ThreatEventSerializer

# Vulnerability ViewSets

class VulnerabilityViewSet(NetBoxModelViewSet):
    queryset = models.Vulnerability.objects.all().order_by('name')
    serializer_class = serializers.VulnerabilitySerializer

# VulnerabilityAssignment ViewSets

class VulnerabilityAssignmentViewSet(NetBoxModelViewSet):
    queryset = models.VulnerabilityAssignment.objects.all().order_by('pk')
    serializer_class = serializers.VulnerabilityAssignmentSerializer

# Risk ViewSets

class RiskViewSet(NetBoxModelViewSet):
    queryset = models.Risk.objects.all().order_by('name')
    serializer_class = serializers.RiskSerializer

# Control ViewSets

class ControlViewSet(NetBoxModelViewSet):
    queryset = models.Control.objects.all().order_by('name')
    serializer_class = serializers.ControlSerializer


# CPEMapping ViewSet

class CPEMappingViewSet(NetBoxModelViewSet):
    queryset = models.CPEMapping.objects.all().order_by('cpe_vendor', 'cpe_product')
    serializer_class = serializers.CPEMappingSerializer
