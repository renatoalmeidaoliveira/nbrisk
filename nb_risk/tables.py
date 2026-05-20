import django_tables2 as tables
from django_tables2.utils import Accessor
from django.utils.safestring import mark_safe

from netbox.tables import NetBoxTable, columns
from netbox.tables.columns import ActionsColumn
from django.db.models import Count

from . import models
from . import columns as riskColumns

# ThreatSource Tables


class ThreatSourceTable(NetBoxTable):

    name = tables.Column(linkify=True)

    class Meta(NetBoxTable.Meta):
        model = models.ThreatSource
        fields = ["name", "threat_type", "capability", "intent", "targeting"]


# ThreatEvent Tables


class ThreatEventTable(NetBoxTable):

    name = tables.Column(linkify=True)

    class Meta(NetBoxTable.Meta):
        model = models.ThreatEvent
        fields = ["name", "threat_source", "relevance", "likelihood", "impact"]


# KEV Badge Column

class KEVColumn(tables.Column):
    """Renders a red KEV badge when the vulnerability is in the CISA catalog."""
    attrs = {"td": {"class": "text-center"}}

    def render(self, value):
        if value:
            return mark_safe(
                '<span class="badge bg-danger" title="CISA Known Exploited Vulnerability">'  
                '<i class="mdi mdi-alert"></i> KEV</span>'
            )
        return mark_safe('<span class="text-muted">&mdash;</span>')


# Vulnerability Tables


class VulnerabilityTable(NetBoxTable):

    name = tables.Column(linkify=True)
    in_kev = KEVColumn(verbose_name='KEV')
    affected = columns.LinkedCountColumn(
        verbose_name="Affected Assets",
        accessor=Accessor("affected_assets"),
        viewname='plugins:nb_risk:vulnerabilityassignment_list',
        url_params={
            'vulnerability': 'name',
        },
    )

    def order_affected(self, queryset, is_descending):
        if is_descending:
            queryset = queryset.annotate(affected_assets=Count('vulnerability_assignments')).order_by('-affected_assets')
        else:
            queryset = queryset.annotate(affected_assets=Count('vulnerability_assignments')).order_by('affected_assets')
        return (queryset, True)

    class Meta(NetBoxTable.Meta):
        model = models.Vulnerability
        fields = ["name", "cve", "in_kev", "description", "affected", "cvssbaseScore"]


# VulnerabilityAssignment Tables


class VulnerabilityAssignmentTable(NetBoxTable):

    actions = columns.ActionsColumn(actions=("delete",))
    vulnerability = tables.Column(linkify=True)

    class Meta(NetBoxTable.Meta):
        model = models.VulnerabilityAssignment
        fields = ["vulnerability", "vulnerability__cve", "vulnerability__description"]


class VulnerabilityAssignmentListTable(NetBoxTable):

    actions = columns.ActionsColumn(actions=("delete",))

    asset = tables.Column(linkify=True)

    asset_object_type = tables.Column(verbose_name="Asset Type")

    class Meta(NetBoxTable.Meta):
        model = models.VulnerabilityAssignment
        fields = ["asset", "asset_object_type"]

class VulnerabilityAssignmentListViewTable(NetBoxTable):
    
        actions = columns.ActionsColumn(actions=("delete",))

        vulnerability = tables.Column(linkify=True)
    
        asset = tables.Column(linkify=True)
    
        asset_object_type = tables.Column(verbose_name="Asset Type")
    
        class Meta(NetBoxTable.Meta):
            model = models.VulnerabilityAssignment
            fields = ["asset", "asset_object_type", "vulnerability", "vulnerability__cve", ]
            default_columns = ('pk', 'asset', "vulnerability")

class VulnerabilityExploitListTable(NetBoxTable):


    asset = tables.Column(linkify=True)

    vulnerability = tables.Column(linkify=True)

    asset_object_type = tables.Column(verbose_name="Asset Type")

    class Meta(NetBoxTable.Meta):
        model = models.VulnerabilityAssignment
        fields = ["asset", "vulnerability", "asset_object_type"]


# Risk Tables


class RiskTable(NetBoxTable):

    name = tables.Column(linkify=True)

    threat_event = tables.Column(linkify=True)

    risk_level = tables.Column(verbose_name="Risk Level")

    class Meta(NetBoxTable.Meta):
        model = models.Risk
        fields = ["name", "threat_event", "likelihood", "impact", "risk_level"]


# CVE Tables


class InKEVColumn(tables.Column):
    """Compact KEV indicator for CVE search results."""
    attrs = {"td": {"class": "text-center text-nowrap"}}

    def render(self, value):
        if value:
            return mark_safe(
                '<span class="badge bg-danger" title="CISA Known Exploited Vulnerability">'  
                '<i class="mdi mdi-alert"></i> KEV</span>'
            )
        return mark_safe('<span class="text-muted">&mdash;</span>')


class CveTable(NetBoxTable):

    id = tables.Column(attrs={"td": {"class": "text-end text-nowrap"}})
    in_kev = InKEVColumn(verbose_name='KEV', default=False)
    description = tables.Column()
    baseScore = tables.Column(verbose_name="Base Score")
    cvssVersion = tables.Column(verbose_name="CVSS Version")
    accessVector = tables.Column(verbose_name="Attack Vector")

    create = riskColumns.CreateColumn(empty_values=())

    class Meta(NetBoxTable.Meta):
        model = models.Vulnerability
        fields = [
            "id",
            "in_kev",
            "description",
            "cvssVersion",
            "baseScore",
            "accessVector",
            "create",
        ]


# Control Tables

class ControlTable(NetBoxTable):
    name = tables.Column(linkify=True)
    class Meta(NetBoxTable.Meta):
        model = models.Control
        fields = ["name",]


# CPEMapping Tables

class CPEMappingTable(NetBoxTable):
    platform = tables.Column(linkify=True)
    device_type = tables.Column(linkify=True)
    cpe_vendor = tables.Column(verbose_name='Vendor')
    cpe_product = tables.Column(verbose_name='Product')
    cpe_part = tables.Column(verbose_name='Part')
    cpe_target_sw = tables.Column(verbose_name='Target SW')
    verified = tables.BooleanColumn(verbose_name='Verified')
    actions = ActionsColumn(actions=('edit', 'delete'))

    class Meta(NetBoxTable.Meta):
        model = models.CPEMapping
        fields = [
            'pk', 'id', 'platform', 'device_type',
            'cpe_part', 'cpe_vendor', 'cpe_product', 'cpe_target_sw',
            'verified', 'actions',
        ]
        default_columns = [
            'platform', 'device_type', 'cpe_part', 'cpe_vendor',
            'cpe_product', 'cpe_target_sw', 'verified', 'actions',
        ]
