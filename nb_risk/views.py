from netbox.views import generic
from dcim.models import Device, Site
from tenancy.models import Tenant
from virtualization.models import VirtualMachine

from extras.plugins import get_plugin_config
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


@register_model_view(models.ThreatEvent, name='vulnerabilities')
class ThreatEventVulnerabilityView(generic.ObjectChildrenView):
    queryset = models.ThreatEvent.objects.all()
    child_model = models.Vulnerability
    table = tables.VulnerabilityExploitListTable
    template_name = "nb_risk/threatevent_vulnerabilities.html"
    tab = ViewTab(label='Exploit Vulnerabilities', badge=lambda obj: obj.vulnerability.all().count(), hide_if_empty=True)

    def get_children(self, request, parent):
            childrens = parent.vulnerability.all()
            return childrens


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


@register_model_view(models.Vulnerability, name='affected_assets')
class VulnerabilityAffectedAssetsView(generic.ObjectChildrenView):
    queryset = models.Vulnerability.objects.all()
    child_model = models.Vulnerability
    table = tables.VulnerabilityAssignmentListTable
    template_name = "nb_risk/vulnerability_affected_assets.html"
    tab = ViewTab(label='Affected Assets', badge=lambda obj: models.VulnerabilityAssignment.objects.filter(vulnerability=obj).count(), hide_if_empty=True)

    def get_children(self, request, parent):
            childrens = models.VulnerabilityAssignment.objects.filter(vulnerability=parent)
            return childrens

    
class VulnerabilityListView(generic.ObjectListView):
    queryset = models.Vulnerability.objects.all()
    table = tables.VulnerabilityTable
    filterset = filters.VulnerabilityFilterSet
    filterset_form = forms.VulnerabilityFilterForm
    template_name = "nb_risk/vulnerability_list.html"


class VulnerabilityEditView(generic.ObjectEditView):
    queryset = models.Vulnerability.objects.all()
    form = forms.VulnerabilityForm

class VulnerabilityBulkImportView(generic.BulkImportView):
    queryset = models.Vulnerability.objects.all()
    model_form = forms.VulnerabilityImportForm

class VulnerabilityDeleteView(generic.ObjectDeleteView):
    queryset = models.Vulnerability.objects.all()


class VulnerabilityBulkDeleteView(generic.BulkDeleteView):
    queryset = models.Vulnerability.objects.all()
    table = tables.VulnerabilityTable


# Generic Vulnerability List View


def create_view(model_representation):

    app_label, model = model_representation.split(".")
    model = ContentType.objects.get(app_label=app_label, model=model).model_class()
    name = f"{model._meta.model_name}-vulnerability_list"
    path = f"{model._meta.model_name}-vulnerability_list"
    base_template_name = f"{model._meta.app_label}/{model._meta.model_name}.html"

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


supported_assets = get_plugin_config("nb_risk", "supported_assets")
additional_assets = get_plugin_config("nb_risk", "additional_assets")
supported_assets = supported_assets + additional_assets

for supported_asset in supported_assets:
    create_view(supported_asset)

# VulnerabilityAssignment Views


class VulnerabilityAssignmentEditView(generic.ObjectEditView):
    queryset = models.VulnerabilityAssignment.objects.all()
    form = forms.VulnerabilityAssignmentForm
    template_name = "nb_risk/generic_vulnerability_assignment_edit.html"

    def alter_object(self, instance, request, args, kwargs):
        if not instance.pk:
            # Assign the object based on URL kwargs
            content_type = get_object_or_404(
                ContentType, pk=request.GET.get("asset_object_type")
            )
            instance.object = get_object_or_404(
                content_type.model_class(), pk=request.GET.get("asset_id")
            )
        return instance

    def get_extra_addanother_params(self, request):
        return {
            "asset_object_type": request.GET.get("asset_object_type"),
            "asset_id": request.GET.get("asset_id"),
        }


class VulnerabilityAssignmentDeleteView(generic.ObjectDeleteView):
    queryset = models.VulnerabilityAssignment.objects.all()

class VulnerabilityAssignmentListView(generic.ObjectListView):
    queryset = models.VulnerabilityAssignment.objects.all()
    table = tables.VulnerabilityExploitListTable
    filterset = filters.VulnerabilityAssignmentFilterSet
    filterset_form = forms.VulnerabilityAssignmentFilterForm
    actions = ('import', 'export', )

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

# Control Views

class ControlListView(generic.ObjectListView):
    queryset = models.Control.objects.all()
    table = tables.ControlTable
    filterset = filters.ControlFilterSet
    filterset_form = forms.ControlFilterForm

class ControlView(generic.ObjectView):
    queryset = models.Control.objects.all()

    def get_extra_context(self, request, instance):
        risks = instance.risk.all()
        thread_events = []
        for risk in risks:
            thread_events.append(risk.threat_event)
        assets = models.VulnerabilityAssignment.objects.filter(threat_events__in=thread_events)
        data = {
            "risks_count": risks.count(),
            "assets_count": assets.count(),
        }
        return data

@register_model_view(models.Control, name='risks')
class ControlRisksView(generic.ObjectChildrenView):
    queryset = models.Control.objects.all()
    child_model = models.Risk
    table = tables.RiskTable
    template_name = "nb_risk/control_risks.html"
    tab = ViewTab(label='Risks', badge=lambda obj: obj.risk.all().count(), hide_if_empty=True)

    def get_children(self, request, parent):
            childrens = parent.risk.all()
            return childrens

def _get_assets(instance):
        risks = instance.risk.all()
        thread_events = []
        for risk in risks:
            thread_events.append(risk.threat_event)
        assets = models.VulnerabilityAssignment.objects.filter(threat_events__in=thread_events)
        return assets

@register_model_view(models.Control, name='assets')
class ControlAssetsView(generic.ObjectChildrenView):
    queryset = models.Control.objects.all()
    child_model = models.VulnerabilityAssignment
    table = tables.VulnerabilityAssignmentListTable
    template_name = "nb_risk/control_assets.html"
    tab = ViewTab(label='Related Assets', badge=lambda obj: _get_assets(obj).count(), hide_if_empty=True)


    def get_children(self, request, parent):
            childrens = _get_assets(parent)
            return childrens

class ControlEditView(generic.ObjectEditView):
    queryset = models.Control.objects.all()
    form = forms.ControlForm

class ControlDeleteView(generic.ObjectDeleteView):
    queryset = models.Control.objects.all()

class ControlBulkDeleteView(generic.BulkDeleteView):
    queryset = models.Control.objects.all()
    table = tables.ControlTable
