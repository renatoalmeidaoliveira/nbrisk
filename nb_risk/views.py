from netbox.views import generic
from dcim.models import Device, Site
from tenancy.models import Tenant
from virtualization.models import VirtualMachine

from utilities.views import ViewTab, register_model_view
from django.contrib.contenttypes.models import ContentType
from django.shortcuts import get_object_or_404

import logging

logger = logging.getLogger(__name__)

from . import forms, models, tables, filters

# ThreatSource Views


class ThreatSourceView(generic.ObjectView):
    queryset = models.ThreatSource.objects.all()


class ThreatSourceListView(generic.ObjectListView):
    queryset = models.ThreatSource.objects.all()
    table = tables.ThreatSourceTable
    filterset = filters.ThreatSourceFilterSet
    filterset_form = forms.ThreatSourceFilterForm


class ThreatSourceEditView(generic.ObjectEditView):
    queryset = models.ThreatSource.objects.all()
    form = forms.ThreatSourceForm


class ThreatSourceDeleteView(generic.ObjectDeleteView):
    queryset = models.ThreatSource.objects.all()


# ThreatEvent Views


class ThreatEventView(generic.ObjectView):
    queryset = models.ThreatEvent.objects.all()

class ThreatEventVulnerabilityView(generic.ObjectView):
    queryset = models.ThreatEvent.objects.all()
    template_name = "nb_risk/threatevent_vulnerabilities.html"

    def get_extra_context(self, request, instance):
        vulnerabilities = instance.vulnerability.all()
        table = tables.VulnerabilityExploitListTable(vulnerabilities)
        data = {
            "tab" : "vulnerabilities",
            "table": table,
        }
        return data

class ThreatEventListView(generic.ObjectListView):
    queryset = models.ThreatEvent.objects.all()
    table = tables.ThreatEventTable
    filterset = filters.ThreatEventFilterSet
    filterset_form = forms.ThreatEventFilterForm


class ThreatEventEditView(generic.ObjectEditView):
    queryset = models.ThreatEvent.objects.all()
    form = forms.ThreatEventForm


class ThreatEventDeleteView(generic.ObjectDeleteView):
    queryset = models.ThreatEvent.objects.all()

class ThreatEventBulkDeleteView(generic.BulkDeleteView):
    queryset = models.ThreatEvent.objects.all()
    table = tables.ThreatEventTable


# Vulnerability Views


class VulnerabilityView(generic.ObjectView):
    queryset = models.Vulnerability.objects.all()

class VulnerabilityAffectedAssetsView(generic.ObjectView):
    queryset = models.Vulnerability.objects.all()
    template_name = "nb_risk/vulnerability_affected_assets.html"

    def get_extra_context(self, request, instance):
        assets = models.VulnerabilityAssignment.objects.filter(vulnerability=instance)
        table = tables.VulnerabilityAssignmentListTable(assets)
        data = {
            "tab" : "affected_assets",
            "table": table,
        }
        return data


class VulnerabilityListView(generic.ObjectListView):
    queryset = models.Vulnerability.objects.all()
    table = tables.VulnerabilityTable
    filterset = filters.VulnerabilityFilterSet
    filterset_form = forms.VulnerabilityFilterForm
    template_name = "nb_risk/vulnerability_list.html"


class VulnerabilityEditView(generic.ObjectEditView):
    queryset = models.Vulnerability.objects.all()
    form = forms.VulnerabilityForm


class VulnerabilityDeleteView(generic.ObjectDeleteView):
    queryset = models.Vulnerability.objects.all()

class VulnerabilityBulkDeleteView(generic.BulkDeleteView):
    queryset = models.Vulnerability.objects.all()
    table = tables.VulnerabilityTable

# Generic Vulnerability List View


def create_view(model, base_template_name):

    name = f"{model._meta.model_name}-vulnerability_list"
    path = f"{model._meta.model_name}-vulnerability_list"

    class View(generic.ObjectChildrenView):
        def __init__(self, *args, **kwargs):
            self.queryset = model.objects.all()
            self.child_model = models.VulnerabilityAssignment
            self.table = tables.VulnerabilityAssignmentTable
            self.template_name = "nb_risk/generic_vulnerability_list.html"
            super().__init__(*args, **kwargs)

        tab = ViewTab(
            label="Vulnerabilities",
            badge=lambda obj: models.VulnerabilityAssignment.objects.filter(
                asset_object_type=ContentType.objects.get_for_model(obj),
                asset_id=obj.id,
            ).count(),
            hide_if_empty=True,
        )

        def get_children(self, request, parent):
            childrens = self.child_model.objects.filter(
                asset_object_type=ContentType.objects.get_for_model(parent),
                asset_id=parent.id,
            )
            return childrens

        def get_extra_context(self, request, instance):
            data = {
                "base_template_name": base_template_name,
            }
            return data

    register_model_view(model, name=name, path=path)(View)


supported_assets = [
    {"model": Device, "template": "dcim/device.html"},
    {"model": VirtualMachine, "template": "virtualization/virtualmachine.html"},
    {"model": Site, "template": "dcim/site.html"},
    {"model": Tenant, "template": "tenancy/tenant.html"},
]
for supported_asset in supported_assets:
    create_view(supported_asset["model"], supported_asset["template"])

# VulnerabilityAssignment Views

class VulnerabilityAssignmentEditView(generic.ObjectEditView):
    queryset = models.VulnerabilityAssignment.objects.all()
    form = forms.VulnerabilityAssignmentForm
    template_name = 'nb_risk/generic_vulnerability_assignment_edit.html'

    def alter_object(self, instance, request, args, kwargs):
        if not instance.pk:
            # Assign the object based on URL kwargs
            content_type = get_object_or_404(ContentType, pk=request.GET.get('asset_object_type'))
            instance.object = get_object_or_404(content_type.model_class(), pk=request.GET.get('asset_id'))
        return instance

    def get_extra_addanother_params(self, request):
        return {
            'asset_object_type': request.GET.get('asset_object_type'),
            'asset_id': request.GET.get('asset_id'),
        }

class VulnerabilityAssignmentDeleteView(generic.ObjectDeleteView):
    queryset = models.VulnerabilityAssignment.objects.all()


# Risk Views

class RiskListView(generic.ObjectListView):
    queryset = models.Risk.objects.all()
    table = tables.RiskTable
    filterset = filters.RiskFilterSet
    filterset_form = forms.RiskFilterForm

class RiskView(generic.ObjectView):
    queryset = models.Risk.objects.all()

class RiskEditView(generic.ObjectEditView):
    queryset = models.Risk.objects.all()
    form = forms.RiskForm

class RiskDeleteView(generic.ObjectDeleteView):
    queryset = models.Risk.objects.all()

class RiskBulkDeleteView(generic.BulkDeleteView):
    queryset = models.Risk.objects.all()
    table = tables.RiskTable