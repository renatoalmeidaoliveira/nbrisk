from django import forms

from netbox.forms import NetBoxModelForm, NetBoxModelFilterSetForm
from dcim.models import Device
from virtualization.models import VirtualMachine

from utilities.forms import (
    BootstrapMixin,
    DatePicker,
    DynamicModelMultipleChoiceField,
    DynamicModelChoiceField,
)
from utilities.forms.fields import DynamicModelChoiceField


from . import models, choices

# ThreatSource Forms


class ThreatSourceForm(NetBoxModelForm):
    class Meta:
        model = models.ThreatSource
        fields = [
            "name",
            "threat_type",
            "capability",
            "intent",
            "targeting",
            "description",
            "notes",
        ]


class ThreatSourceFilterForm(NetBoxModelFilterSetForm):
    model = models.ThreatSource

    class Meta:
        fields = ["name", "threat_type", "capability", "intent", "targeting"]


# ThreatEvent Forms


class ThreatEventForm(NetBoxModelForm):
    class Meta:
        model = models.ThreatEvent
        fields = [
            "name",
            "threat_source",
            "description",
            "notes",
            "relevance",
            "likelihood",
            "impact",
            "vulnerability",
        ]


class ThreatEventFilterForm(NetBoxModelFilterSetForm):
    model = models.ThreatEvent

    class Meta:
        fields = [
            "name",
            "threat_source",
            "relevance",
            "likelihood",
            "impact",
            "vulnerability",
        ]


# Vulnerability Forms


class VulnerabilityForm(NetBoxModelForm):
    class Meta:
        model = models.Vulnerability
        fields = ["name", "cve", "description", "notes"]


class VulnerabilityFilterForm(NetBoxModelFilterSetForm):
    model = models.Vulnerability

    class Meta:
        fields = ["name", "cve"]

# VulnerabilityAssignment Forms

class VulnerabilityAssignmentForm(NetBoxModelForm):
    class Meta:
        model = models.VulnerabilityAssignment
        fields = ["asset_object_type", "asset_id", "vulnerability"]

class VulnerabilityAssignmentFilterForm(NetBoxModelFilterSetForm):
    model = models.VulnerabilityAssignment

    class Meta:
        fields = ["vulnerability"]
        