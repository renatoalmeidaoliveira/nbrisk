from netbox.views import generic
from dcim.models import Device
from virtualization.models import VirtualMachine
from utilities.views import ViewTab, register_model_view
from django.contrib.contenttypes.models import ContentType

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


# Vulnerability Views


class VulnerabilityView(generic.ObjectView):
    queryset = models.Vulnerability.objects.all()


class VulnerabilityListView(generic.ObjectListView):
    queryset = models.Vulnerability.objects.all()
    table = tables.VulnerabilityTable
    filterset = filters.VulnerabilityFilterSet
    filterset_form = forms.VulnerabilityFilterForm


class VulnerabilityEditView(generic.ObjectEditView):
    queryset = models.Vulnerability.objects.all()
    form = forms.VulnerabilityForm


class VulnerabilityDeleteView(generic.ObjectDeleteView):
    queryset = models.Vulnerability.objects.all()




@register_model_view(Device, name='device-vulnerability_list', path='device-vulnerability_list')
class DeviceVulnerabilityListView(generic.ObjectChildrenView):
    
    queryset = Device.objects.all()
    child_model = models.VulnerabilityAssignment
    table = tables.VulnerabilityAssignmentTable
    template_name = 'nb_risk/device_vulnerability_list.html'
    
    tab = ViewTab(
        label='Vulnerabilities',
        badge=lambda obj: models.VulnerabilityAssignment.objects.filter(asset_object_type=ContentType.objects.get_for_model(obj), asset_id=obj.id).count(),
        hide_if_empty=True
    )

    def get_children(self, request, parent):
        childrens = self.child_model.objects.filter(asset_object_type=ContentType.objects.get_for_model(parent), asset_id=parent.id)
        return childrens

