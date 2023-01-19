import django_tables2 as tables

from netbox.tables import NetBoxTable, ChoiceFieldColumn, columns

from . import models

# ThreatSource Tables


class ThreatSourceTable(NetBoxTable):
    class Meta(NetBoxTable.Meta):
        model = models.ThreatSource
        fields = ["name", "threat_type", "capability", "intent", "targeting"]


# ThreatEvent Tables


class ThreatEventTable(NetBoxTable):
    class Meta(NetBoxTable.Meta):
        model = models.ThreatEvent
        fields = ["name", "threat_source", "relevance", "likelihood", "impact"]


# Vulnerability Tables


class VulnerabilityTable(NetBoxTable):
    class Meta(NetBoxTable.Meta):
        model = models.Vulnerability
        fields = ["name", "cve", "description", "asset"]


# VulnerabilityAssignment Tables


class VulnerabilityAssignmentTable(NetBoxTable):

    actions = columns.ActionsColumn(actions=())

    class Meta(NetBoxTable.Meta):
        model = models.VulnerabilityAssignment
        fields = ["vulnerability", "vulnerability__cve", "vulnerability__description"]
