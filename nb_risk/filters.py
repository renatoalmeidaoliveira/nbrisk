from netbox.filtersets import NetBoxModelFilterSet
from . import models

# ThreatSource Filters


class ThreatSourceFilterSet(NetBoxModelFilterSet):
    class Meta:
        model = models.ThreatSource
        fields = ["threat_type", "capability", "intent", "targeting"]


# ThreatEvent Filters


class ThreatEventFilterSet(NetBoxModelFilterSet):
    class Meta:
        model = models.ThreatEvent
        fields = ["threat_source", "relevance", "likelihood", "impact"]


# Vulnerability Filters


class VulnerabilityFilterSet(NetBoxModelFilterSet):
    class Meta:
        model = models.Vulnerability
        fields = ["name", "cve"]


# VulnerabilityAssignment Filters


class VulnerabilityAssignmentFilterSet(NetBoxModelFilterSet):
    class Meta:
        model = models.VulnerabilityAssignment
        fields = ["vulnerability"]

# Risk Filters

class RiskFilterSet(NetBoxModelFilterSet):
    class Meta:
        model = models.Risk
        fields = ["name", "threat_event", "description", "impact", "likelihood"]
