from django import forms

from netbox.forms import NetBoxModelForm, NetBoxModelFilterSetForm, NetBoxModelImportForm
from dcim.models import Device, DeviceType
from virtualization.models import VirtualMachine

from utilities.forms import (
    BootstrapMixin,
    DatePicker,
    CommentField,
    DynamicModelMultipleChoiceField,
    SlugField,
    DynamicModelChoiceField,
)

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

    vulnerability = DynamicModelMultipleChoiceField(
        queryset=models.VulnerabilityAssignment.objects.all(),
        required=True,
    )

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

    fieldsets = (
        ("Vulnerability", ("name", "cve", "description", "notes"),),
        ("CVSSv2 Score", ("cvssaccessVector", "cvssaccessComplexity", "cvssauthentication", "cvssconfidentialityImpact", "cvssintegrityImpact", "cvssavailabilityImpact", "cvssbaseScore")),
    )
    class Meta:
        model = models.Vulnerability
        fields = [
            "name",
            "cve",
            "description",
            "notes",
            "cvssaccessVector",
            "cvssaccessComplexity",
            "cvssauthentication",
            "cvssconfidentialityImpact",
            "cvssintegrityImpact",
            "cvssavailabilityImpact",
            "cvssbaseScore",
        ]


class VulnerabilityFilterForm(NetBoxModelFilterSetForm):
    model = models.Vulnerability

    class Meta:
        fields = ["name", "cve"]


class VulnerabilitySearchFilterForm(NetBoxModelFilterSetForm):
    model = models.Vulnerability
    q = forms.CharField(label="cpeName", required=False)

    device_type = DynamicModelChoiceField(
        queryset=DeviceType.objects.all(),
        required=False,
    )
    version = forms.CharField(required=False)

    part = forms.ChoiceField(
        choices=choices.CVE_PART_CHOICES,
        required=False,
    )

class VulnerabilityImportForm(NetBoxModelImportForm):
    class Meta:
        model = models.Vulnerability
        fields = [
            "name",
            "cve",
            "description",
            "notes",
            "cvssaccessVector",
            "cvssaccessComplexity",
            "cvssauthentication",
            "cvssconfidentialityImpact",
            "cvssintegrityImpact",
            "cvssavailabilityImpact",
            "cvssbaseScore",
        ]

# VulnerabilityAssignment Forms


class VulnerabilityAssignmentForm(BootstrapMixin, forms.ModelForm):

    vulnerability = DynamicModelChoiceField(
        queryset=models.Vulnerability.objects.all(),
        required=True,
    )

    class Meta:
        model = models.VulnerabilityAssignment
        fields = ["asset_object_type", "asset_id", "vulnerability"]
        widgets = {
            "asset_object_type": forms.HiddenInput(),
            "asset_id": forms.HiddenInput(),
        }


class VulnerabilityAssignmentFilterForm(NetBoxModelFilterSetForm):
    model = models.VulnerabilityAssignment

    class Meta:
        fields = ["vulnerability"]


# Risk Forms


class RiskForm(NetBoxModelForm):
    class Meta:
        model = models.Risk
        fields = [
            "name",
            "threat_event",
            "description",
            "notes",
            "likelihood",
            "impact",
        ]


class RiskFilterForm(NetBoxModelFilterSetForm):
    model = models.Risk

    class Meta:
        fields = ["name", "threat_event", "description", "impact", "likelihood"]

# Control Forms

class ControlForm(NetBoxModelForm):
    class Meta:
        model = models.Control
        fields = [
            "name",
            "description",
            "notes",
            "category",
            "risk",
        ]

class ControlFilterForm(NetBoxModelFilterSetForm):
    model = models.Control

    class Meta:
        fields = [
            "name",
            "description",
            "notes",
            "category",
            "risk",
        ]